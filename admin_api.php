<?php
session_start();


define('K_FACTOR', 300);

// --- HELPER FUNCTIONS ---
function send_json_response($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function calculate_level($score) {
    if ($score < 100) return 0;
    return floor(sqrt($score / 100));
}

function calculate_score_change($winner, $loser) {
    $expected_win_prob = 1.0 / (1.0 + pow(10, ($loser['score'] - $winner['score']) / 400));
    $winner_gain = round(K_FACTOR * (1 - $expected_win_prob));
    $winner_gain = max($winner_gain, 1);
    $loser_gain = round((K_FACTOR / 4) * $expected_win_prob);
    $loser_gain = max($loser_gain, 1);
    return [
        'winner_new_score' => $winner['score'] + $winner_gain,
        'loser_new_score' => $loser['score'] + $loser_gain,
        'winner_gain' => $winner_gain,
        'loser_gain' => $loser_gain
    ];
}

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : '');

    // Define public actions that do not require a login
    $public_actions = ['login', 'get_tournaments', 'get_round_pairings', 'get_player', 'get_history'];

    // If the action is NOT public, then we must be logged in.
    if (!in_array($action, $public_actions)) {
        if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
            send_json_response(['error' => 'Not authenticated.'], 403);
        }
    }
    
    // Handle all actions in a single switch
    switch ($action) {
        case 'login':
            if (isset($_POST['password']) && $_POST['password'] == $admin_password) {
                $_SESSION['loggedin'] = true;
                send_json_response(['success' => true]);
            } else { send_json_response(['error' => 'Invalid password.'], 401); }
            break;

        case 'get_tournaments':
            $stmt = $conn->prepare("SELECT * FROM tournaments WHERE status != 'archived' ORDER BY created_at DESC");
            $stmt->execute();
            send_json_response($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        case 'get_round_pairings':
            if (!isset($_POST['tournament_id'])) { send_json_response(['error' => 'Tournament ID not provided.'], 400); }
            $tournament_id = $_POST['tournament_id'];
            $stmt_tourney = $conn->prepare("SELECT name, current_round FROM tournaments WHERE tournament_id = ?");
            $stmt_tourney->execute([$tournament_id]);
            $tournament_info = $stmt_tourney->fetch(PDO::FETCH_ASSOC);
            $stmt_pairings = $conn->prepare("
                SELECT tr.*, p1.name as p1_name, p2.name as p2_name 
                FROM tournament_rounds tr
                LEFT JOIN competitors p1 ON tr.player1_id = p1.id
                LEFT JOIN competitors p2 ON tr.player2_id = p2.id
                WHERE tr.tournament_id = ? ORDER BY tr.round_number ASC, tr.round_match_id ASC
            ");
            $stmt_pairings->execute([$tournament_id]);
            $all_matches = $stmt_pairings->fetchAll(PDO::FETCH_ASSOC);
            $rounds = [];
            foreach($all_matches as $match) {
                $rounds[$match['round_number']][] = $match;
            }
            send_json_response(['name' => $tournament_info['name'], 'current_round' => $tournament_info['current_round'], 'rounds' => $rounds]);
            break;

        case 'get_player':
            if (!isset($_GET['id'])) { send_json_response(['error' => 'Player ID not provided.'], 400); }
            $id = $_GET['id'];
            $stmt = $conn->prepare("SELECT * FROM competitors WHERE id = :id");
            $stmt->bindParam(':id', $id);
            $stmt->execute();
            $competitor = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($competitor) {
                $competitor['level'] = calculate_level($competitor['score']);
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
                send_json_response($competitor);
            } else { http_response_code(404); send_json_response(['error' => 'Competitor not found.']); }
            break;
        
        case 'get_history':
            if (!isset($_GET['id'])) { send_json_response(['error' => 'Player ID not provided.'], 400); }
            $id = $_GET['id'];
            $stmt = $conn->prepare("
                SELECT m.match_time, m.winner_id, w.name as winner_name, m.loser_id, l.name as loser_name, m.winner_score_change, m.loser_score_change
                FROM matches m
                JOIN competitors w ON m.winner_id = w.id
                JOIN competitors l ON m.loser_id = l.id
                WHERE m.winner_id = :id OR m.loser_id = :id
                ORDER BY m.match_time DESC
            ");
            $stmt->bindParam(':id', $id);
            $stmt->execute();
            send_json_response($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        case 'check_status':
            send_json_response(['loggedin' => true]);
            break;

        case 'logout':
            session_unset();
            session_destroy();
            send_json_response(['success' => true]);
            break;
            
        case 'get_competitors':
            $stmt = $conn->prepare("SELECT * FROM competitors");
            $stmt->execute();
            $competitors = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach($competitors as $key => $competitor) {
                $competitors[$key]['level'] = calculate_level($competitor['score']);
            }
            send_json_response($competitors);
            break;
            
        case 'add_competitor':
            $conn->beginTransaction();
            try {
                $stmt_count = $conn->prepare("SELECT COUNT(*) FROM competitors");
                $stmt_count->execute();
                $new_rank = $stmt_count->fetchColumn() + 1;
                $new_pin = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
                $stmt_id = $conn->prepare("SELECT id FROM competitors WHERE id LIKE 'C%' ORDER BY CAST(SUBSTRING(id, 2) AS UNSIGNED) DESC LIMIT 1");
                $stmt_id->execute();
                $last_id_row = $stmt_id->fetch(PDO::FETCH_ASSOC);
                $new_id_num = 101;
                if ($last_id_row) {
                    $last_id_num = (int) substr($last_id_row['id'], 1);
                    $new_id_num = $last_id_num + 1;
                }
                $new_id = 'C' . $new_id_num;
                $stmt = $conn->prepare("INSERT INTO competitors (id, name, pin, score, rank, avatarImage) VALUES (?, ?, ?, 0, ?, ?)");
                $stmt->execute([$new_id, $_POST['name'], $new_pin, $new_rank, $_POST['avatarImage'] ?? null]);
                $conn->commit();
                send_json_response(['success' => true, 'message' => "Competitor added with ID: $new_id."]);
            } catch (Exception $e) { $conn->rollBack(); send_json_response(['error' => 'Failed to add competitor.'], 500); }
            break;
            
        case 'update_competitor':
            $stmt_pin = $conn->prepare("SELECT pin FROM competitors WHERE id = ?");
            $stmt_pin->execute([$_POST['id']]);
            $current_pin = $stmt_pin->fetchColumn();
            if (empty($current_pin)) {
                $current_pin = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
            }
            $gamesPlayed = (int)$_POST['wins'] + (int)$_POST['losses'];
            $stmt = $conn->prepare("UPDATE competitors SET name = ?, score = ?, gamesPlayed = ?, wins = ?, losses = ?, avatarImage = ?, pin = ? WHERE id = ?");
            $stmt->execute([
                $_POST['name'], $_POST['score'], $gamesPlayed, 
                $_POST['wins'], $_POST['losses'], $_POST['avatarImage'], $current_pin, $_POST['id']
            ]);
            send_json_response(['success' => true, 'message' => 'Competitor updated.']);
            break;
            
        case 'record_match':
            $winner_id = $_POST['winner_id'];
            $loser_id = $_POST['loser_id'];
            $round_match_id = $_POST['round_match_id'] ?? null;
            $conn->beginTransaction();
            try {
                $stmt_winner = $conn->prepare("SELECT * FROM competitors WHERE id = ? FOR UPDATE");
                $stmt_winner->execute([$winner_id]);
                $winner = $stmt_winner->fetch(PDO::FETCH_ASSOC);
                $stmt_loser = $conn->prepare("SELECT * FROM competitors WHERE id = ? FOR UPDATE");
                $stmt_loser->execute([$loser_id]);
                $loser = $stmt_loser->fetch(PDO::FETCH_ASSOC);
                if (!$winner || !$loser) { throw new Exception("One or both competitors not found."); }
                $score_changes = calculate_score_change($winner, $loser);
                $stmt_update_winner = $conn->prepare("UPDATE competitors SET score = ?, wins = wins + 1, gamesPlayed = gamesPlayed + 1 WHERE id = ?");
                $stmt_update_winner->execute([$score_changes['winner_new_score'], $winner_id]);
                $stmt_update_loser = $conn->prepare("UPDATE competitors SET score = ?, losses = losses + 1, gamesPlayed = gamesPlayed + 1 WHERE id = ?");
                $stmt_update_loser->execute([$score_changes['loser_new_score'], $loser_id]);
                $stmt_log_match = $conn->prepare("INSERT INTO matches (winner_id, loser_id, winner_score_change, loser_score_change) VALUES (?, ?, ?, ?)");
                $stmt_log_match->execute([$winner_id, $loser_id, $score_changes['winner_gain'], $score_changes['loser_gain']]);
                if ($round_match_id) {
                    $stmt_update_round = $conn->prepare("UPDATE tournament_rounds SET winner_id = ? WHERE round_match_id = ?");
                    $stmt_update_round->execute([$winner_id, $round_match_id]);
                }
                $conn->commit();
                send_json_response(['success' => true, 'message' => "Match recorded."]);
            } catch (Exception $e) { $conn->rollBack(); send_json_response(['error' => 'Failed to record match: ' . $e->getMessage()], 500); }
            break;
            
        case 'delete_competitor':
            $stmt = $conn->prepare("DELETE FROM competitors WHERE id = ?");
            $stmt->execute([$_POST['id']]);
            send_json_response(['success' => true, 'message' => 'Competitor deleted.']);
            break;
            
        case 'recalculate_ranks':
            $conn->beginTransaction();
            try {
                $select_stmt = $conn->prepare("SELECT id FROM competitors ORDER BY score DESC");
                $select_stmt->execute();
                $competitors = $select_stmt->fetchAll(PDO::FETCH_ASSOC);
                $rank = 1;
                foreach ($competitors as $competitor) {
                    $update_stmt = $conn->prepare("UPDATE competitors SET rank = ? WHERE id = ?");
                    $update_stmt->execute([$rank, $competitor['id']]);
                    $rank++;
                }
                $conn->commit();
                send_json_response(['success' => true, 'message' => 'Ranks have been recalculated.']);
            } catch (Exception $e) { $conn->rollBack(); send_json_response(['error' => 'Failed to recalculate ranks: ' . $e->getMessage()], 500); }
            break;
            
        case 'create_tournament':
            $stmt = $conn->prepare("INSERT INTO tournaments (name) VALUES (?)");
            $stmt->execute([$_POST['name']]);
            send_json_response(['success' => true, 'message' => 'New tournament created.']);
            break;
            
        case 'get_tournament_details':
            $tournament_id = $_POST['tournament_id'];
            $stmt = $conn->prepare("SELECT tp.*, c.name, c.rank FROM tournament_players tp JOIN competitors c ON tp.player_id = c.id WHERE tp.tournament_id = ? ORDER BY c.rank ASC");
            $stmt->execute([$tournament_id]);
            $players = $stmt->fetchAll(PDO::FETCH_ASSOC);
            send_json_response(['players' => $players]);
            break;

        case 'assign_player_to_tournament':
            $stmt = $conn->prepare("INSERT IGNORE INTO tournament_players (tournament_id, player_id) VALUES (?, ?)");
            $stmt->execute([$_POST['tournament_id'], $_POST['player_id']]);
            send_json_response(['success' => true]);
            break;

        case 'remove_player_from_tournament':
            $stmt = $conn->prepare("DELETE FROM tournament_players WHERE tournament_id = ? AND player_id = ?");
            $stmt->execute([$_POST['tournament_id'], $_POST['player_id']]);
            send_json_response(['success' => true]);
            break;
            
        case 'archive_tournament':
            $tournament_id = $_POST['tournament_id'];
            $stmt = $conn->prepare("UPDATE tournaments SET status = 'archived' WHERE tournament_id = ?");
            $stmt->execute([$tournament_id]);
            send_json_response(['success' => true, 'message' => 'Tournament archived successfully.']);
            break;

        case 'generate_round_1':
            $tournament_id = $_POST['tournament_id'];
            $conn->beginTransaction();
            try {
                $stmt = $conn->prepare("SELECT c.id FROM competitors c JOIN tournament_players tp ON c.id = tp.player_id WHERE tp.tournament_id = ? ORDER BY c.rank ASC, c.score DESC");
                $stmt->execute([$tournament_id]);
                $players = $stmt->fetchAll(PDO::FETCH_COLUMN);
                if (count($players) < 2) { throw new Exception("Not enough players to generate a round."); }

                $num_players = count($players);
                $next_power_of_2 = pow(2, ceil(log($num_players, 2)));
                $num_byes = $next_power_of_2 - $num_players;
                
                $players_with_byes = array_slice($players, 0, $num_byes);
                $players_in_matches = array_slice($players, $num_byes);
                $num_matches_round_1 = count($players_in_matches) / 2;

                $pairings = [];
                for ($i = 0; $i < $num_matches_round_1; $i++) {
                    $pairings[] = [$players_in_matches[$i], $players_in_matches[count($players_in_matches) - 1 - $i]];
                }
                
                $stmt_insert = $conn->prepare("INSERT INTO tournament_rounds (tournament_id, round_number, player1_id, player2_id) VALUES (?, 1, ?, ?)");
                foreach($pairings as $pair) {
                    $stmt_insert->execute([$tournament_id, $pair[0], $pair[1]]);
                }
                
                if ($num_byes > 0) {
                    $stmt_bye = $conn->prepare("INSERT INTO tournament_rounds (tournament_id, round_number, player1_id, player2_id, winner_id) VALUES (?, 1, ?, NULL, ?)");
                    foreach($players_with_byes as $player_with_bye) {
                        $stmt_bye->execute([$tournament_id, $player_with_bye, $player_with_bye]);
                    }
                }
                
                $stmt_update = $conn->prepare("UPDATE tournaments SET status = 'active', current_round = 1 WHERE tournament_id = ?");
                $stmt_update->execute([$tournament_id]);

                $conn->commit();
                send_json_response(['success' => true, 'message' => 'Round 1 generated successfully.']);
            } catch (Exception $e) { $conn->rollBack(); send_json_response(['error' => $e->getMessage()], 500); }
            break;
    }
} catch (PDOException $e) {
    send_json_response(['error' => 'Database error: ' . $e->getMessage()], 500);
}

$conn = null;
?>
