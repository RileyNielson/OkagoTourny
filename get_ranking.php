<?php
// --- DATABASE CONNECTION ---
// IMPORTANT: Replace these values with your actual database credentials from Hostinger.

// Helper function to calculate level
function calculate_level($score) {
    if ($score < 100) {
        return 0;
    }
    return floor(sqrt($score / 100));
}

// --- HEADERS ---
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $action = isset($_GET['action']) ? $_GET['action'] : 'get_player';
    $id = isset($_GET['id']) ? $_GET['id'] : null;

    if ($action == 'get_player' && $id) {
        // --- FETCH SINGLE PLAYER ---
        $stmt = $conn->prepare("SELECT * FROM competitors WHERE id = :id");
        $stmt->bindParam(':id', $id);
        $stmt->execute();
        $competitor = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($competitor) {
            $competitor['level'] = calculate_level($competitor['score']);
            
            // Check if this player has a match staged in a tournament that has not been decided
            $stmt_staged = $conn->prepare("SELECT * FROM tournament_rounds WHERE (player1_id = :id OR player2_id = :id) AND winner_id IS NULL LIMIT 1");
            $stmt_staged->bindParam(':id', $id);
            $stmt_staged->execute();
            $staged_match = $stmt_staged->fetch(PDO::FETCH_ASSOC);

            if ($staged_match) {
                $opponent_id = ($staged_match['player1_id'] == $id) ? $staged_match['player2_id'] : $staged_match['player1_id'];
                if ($opponent_id) {
                    $stmt_opponent = $conn->prepare("SELECT name FROM competitors WHERE id = ?");
                    $stmt_opponent->execute([$opponent_id]);
                    $opponent_name = $stmt_opponent->fetchColumn();
                    $competitor['staged_match'] = ['opponent_id' => $opponent_id, 'opponent_name' => $opponent_name];
                }
            }
            echo json_encode($competitor);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Competitor not found.']);
        }
    } elseif ($action == 'get_history' && $id) {
        // --- FETCH MATCH HISTORY ---
        $stmt = $conn->prepare("
            SELECT 
                m.match_time, m.winner_id, w.name as winner_name,
                m.loser_id, l.name as loser_name,
                m.winner_score_change, m.loser_score_change
            FROM matches m
            JOIN competitors w ON m.winner_id = w.id
            JOIN competitors l ON m.loser_id = l.id
            WHERE m.winner_id = :id OR m.loser_id = :id
            ORDER BY m.match_time DESC
        ");
        $stmt->bindParam(':id', $id);
        $stmt->execute();
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    } else { 
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action or missing parameters.']);
    }

} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}

$conn = null;
?>
