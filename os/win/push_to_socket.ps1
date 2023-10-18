$tcpconn = New-Object System.Net.Sockets.TcpClient("127.0.0.1", "5740")
$tcpstream = $tcpconn.GetStream()

$writer = New-Object System.IO.StreamWriter($tcpstream)
$writer.AutoFlush = $true

$writer.WriteLine($args[0])
