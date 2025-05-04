"""HTML templates and web interface definitions"""

# Login page template
LOGIN_PAGE_TEMPLATE = """HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
    <title>Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        form { display: inline-block; text-align: left; padding: 20px; border: 1px solid #ddd; }
        input { margin: 5px; padding: 5px; }
        button { padding: 8px; background: blue; color: white; border: none; }
        .error { color: red; }
    </style>
</head>
<body>
    <h2>Secure Corporate Login</h2>
    <p>Enter your credentials:</p>
    <form action="/login" method="POST">
        <label>Username:</label> <input type="text" name="username"><br>
        <label>Password:</label> <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br>{error_message}<br>
</body>
</html>
"""

# Admin panel template
ADMIN_PANEL = """HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
    <title>Company Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #ddd; }
    </style>
</head>
<body>
    <h1>Welcome to Company Admin Portal</h1>
    <h2>Company Employee Directory</h2>
    <table border="1" style="width:100%; text-align:left;">
        <tr>
            <th>Name</th>
            <th>Department</th>
            <th>Email</th>
            <th>Phone</th>
        </tr>
        <tr>
            <td>John Doe</td>
            <td>IT Security</td>
            <td>jdoe@company.com</td>
            <td>(555) 123-4567</td>
        </tr>
        <tr>
            <td>Jane Smith</td>
            <td>Finance</td>
            <td>jsmith@company.com</td>
            <td>(555) 234-5678</td>
        </tr>
        <tr>
            <td>Mike Johnson</td>
            <td>HR</td>
            <td>mjohnson@company.com</td>
            <td>(555) 345-6789</td>
        </tr>
    </table>
</body>
</html>
"""

# Access denied template
ACCESS_DENIED = """HTTP/1.1 403 Forbidden
Content-Type: text/html

<html>
<head><title>Access Denied</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>Invalid credentials detected.</p>
</body>
</html>
"""

# Dashboard template
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .dashboard {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            flex: 1;
            min-width: 300px;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 15px;
            flex: 1;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Honeypot Security Dashboard</h1>
            <p>Real-time attack monitoring and visualization</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="totalAttacks">-</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uniqueIPs">-</div>
                <div class="stat-label">Unique Attackers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="topService">-</div>
                <div class="stat-label">Most Targeted Service</div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h2>Recent Attacks</h2>
                <table id="attacksTable">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Service</th>
                            <th>Attack Type</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="attacksTableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalAttacks').textContent = data.total_attacks;
                    document.getElementById('uniqueIPs').textContent = data.unique_ips;
                    document.getElementById('topService').textContent = data.top_service;
                });

            fetch('/api/attacks')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('attacksTableBody');
                    tableBody.innerHTML = '';
                    
                    data.forEach(attack => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${new Date(attack.timestamp).toLocaleString()}</td>
                            <td>${attack.ip}</td>
                            <td>${attack.service}</td>
                            <td>${attack.exploit}</td>
                            <td>${attack.payload}</td>
                        `;
                        tableBody.appendChild(row);
                    });
                });
        }

        // Update dashboard every 5 seconds
        setInterval(updateDashboard, 5000);
        updateDashboard();  // Initial update
    </script>
</body>
</html>
"""