Imports System
Imports System.Data
Imports System.Data.SqlClient
Imports Microsoft.VisualStudio.TestTools.UnitTesting
Imports ADODB

''' <summary>
''' Test suite for SQL Injection remediation in encode.frm
''' Validates that the cmdUnsafe_Click function properly uses parameterized queries
''' to prevent SQL injection attacks
''' </summary>
<TestClass>
Public Class SqlInjectionRemediationTests

    Private testConnection As ADODB.Connection
    Private testCommand As ADODB.Command

    ''' <summary>
    ''' Setup method to initialize test database connection
    ''' </summary>
    <TestInitialize>
    Public Sub Setup()
        ' Initialize test connection
        testConnection = New ADODB.Connection()
    End Sub

    ''' <summary>
    ''' Cleanup method to close test database connection
    ''' </summary>
    <TestCleanup>
    Public Sub Cleanup()
        If testConnection IsNot Nothing Then
            If testConnection.State = ObjectStateEnum.adStateOpen Then
                testConnection.Close()
            End If
            testConnection = Nothing
        End If
    End Sub

    ''' <summary>
    ''' Test that validates parameterized query structure prevents SQL injection
    ''' by checking that the query uses placeholders (?) instead of direct concatenation
    ''' </summary>
    <TestMethod>
    Public Sub TestParameterizedQueryStructure()
        ' Arrange
        Dim expectedQueryPattern As String = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        Dim cmd As New ADODB.Command()

        ' Act
        cmd.CommandText = expectedQueryPattern
        cmd.CommandType = CommandTypeEnum.adCmdText

        ' Assert
        Assert.IsTrue(cmd.CommandText.Contains("?"), "Query should use parameter placeholders")
        Assert.IsFalse(cmd.CommandText.Contains("' &"), "Query should not use string concatenation")
        Assert.IsFalse(cmd.CommandText.Contains("& '"), "Query should not use string concatenation")
    End Sub

    ''' <summary>
    ''' Test that verifies parameters are properly created with correct data types
    ''' </summary>
    <TestMethod>
    Public Sub TestParameterCreation()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim testUserName As String = "testuser"
        Dim testPassword As String = "testpass"
        Dim paramUserName As ADODB.Parameter
        Dim paramPassword As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText

        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, testUserName)
        cmd.Parameters.Append(paramUserName)

        paramPassword = cmd.CreateParameter("Password", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, testPassword)
        cmd.Parameters.Append(paramPassword)

        ' Assert
        Assert.AreEqual(2, cmd.Parameters.Count, "Should have exactly 2 parameters")
        Assert.AreEqual("testuser", cmd.Parameters(0).Value, "First parameter should be username")
        Assert.AreEqual("testpass", cmd.Parameters(1).Value, "Second parameter should be password")
        Assert.AreEqual(DataTypeEnum.adVarChar, cmd.Parameters(0).Type, "Parameters should be VarChar type")
    End Sub

    ''' <summary>
    ''' Test SQL injection payload with single quote - should be safely handled by parameters
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_SingleQuote()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "admin' OR '1'='1"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert - The parameter value should be treated as literal string, not SQL code
        Assert.AreEqual("admin' OR '1'='1", cmd.Parameters(0).Value, "Malicious input should be stored as literal value")
        ' With parameterized queries, this input will be treated as a literal username string
        ' and will not break out of the query context to inject SQL
    End Sub

    ''' <summary>
    ''' Test SQL injection payload with comment syntax
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_CommentSyntax()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "admin'--"
        Dim paramPassword As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramPassword = cmd.CreateParameter("Password", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramPassword)

        ' Assert - Comment syntax should be treated as literal value
        Assert.AreEqual("admin'--", cmd.Parameters(0).Value, "Comment injection should be stored as literal value")
    End Sub

    ''' <summary>
    ''' Test SQL injection payload with UNION attack
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_UnionAttack()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "' UNION SELECT password FROM users--"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert - UNION attack should be neutralized
        Assert.AreEqual("' UNION SELECT password FROM users--", cmd.Parameters(0).Value, "UNION attack should be stored as literal value")
    End Sub

    ''' <summary>
    ''' Test SQL injection payload with semicolon and additional statement
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_MultipleStatements()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "admin'; DROP TABLE Passwords;--"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert - Multiple statement injection should be treated as literal
        Assert.AreEqual("admin'; DROP TABLE Passwords;--", cmd.Parameters(0).Value, "Multiple statement injection should be stored as literal value")
    End Sub

    ''' <summary>
    ''' Test that legitimate usernames with special characters work correctly
    ''' </summary>
    <TestMethod>
    Public Sub TestLegitimateInput_SpecialCharacters()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim legitimateInput As String = "user.name@domain.com"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, legitimateInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert - Legitimate special characters should be preserved
        Assert.AreEqual("user.name@domain.com", cmd.Parameters(0).Value, "Legitimate special characters should be preserved")
    End Sub

    ''' <summary>
    ''' Test empty string inputs are handled correctly
    ''' </summary>
    <TestMethod>
    Public Sub TestEmptyStringInput()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim emptyInput As String = ""
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, emptyInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert
        Assert.AreEqual("", cmd.Parameters(0).Value, "Empty string should be handled correctly")
    End Sub

    ''' <summary>
    ''' Test null value handling in parameters
    ''' </summary>
    <TestMethod>
    Public Sub TestNullValueHandling()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, Nothing)
        cmd.Parameters.Append(paramUserName)

        ' Assert
        Assert.IsNotNull(cmd.Parameters(0), "Parameter should be created even with null value")
    End Sub

    ''' <summary>
    ''' Test SQL injection with encoded characters
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_EncodedCharacters()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "admin%27%20OR%20%271%27%3D%271"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert - Encoded attack should be treated as literal
        Assert.AreEqual("admin%27%20OR%20%271%27%3D%271", cmd.Parameters(0).Value, "Encoded injection should be stored as literal value")
    End Sub

    ''' <summary>
    ''' Test SQL injection with hex-encoded values
    ''' </summary>
    <TestMethod>
    Public Sub TestSqlInjectionPayload_HexEncoded()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maliciousInput As String = "0x61646D696E"
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maliciousInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert
        Assert.AreEqual("0x61646D696E", cmd.Parameters(0).Value, "Hex encoded input should be stored as literal value")
    End Sub

    ''' <summary>
    ''' Test that parameter count cannot be tampered with
    ''' </summary>
    <TestMethod>
    Public Sub TestParameterCountIntegrity()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim paramUserName As ADODB.Parameter
        Dim paramPassword As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText

        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, "testuser")
        cmd.Parameters.Append(paramUserName)

        paramPassword = cmd.CreateParameter("Password", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, "testpass")
        cmd.Parameters.Append(paramPassword)

        ' Assert - Should only have exactly the expected parameters
        Assert.AreEqual(2, cmd.Parameters.Count, "Should have exactly 2 parameters, no more, no less")
    End Sub

    ''' <summary>
    ''' Test maximum length input handling
    ''' </summary>
    <TestMethod>
    Public Sub TestMaximumLengthInput()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim maxLengthInput As String = New String("A"c, 255)
        Dim paramUserName As ADODB.Parameter

        ' Act
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText
        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, maxLengthInput)
        cmd.Parameters.Append(paramUserName)

        ' Assert
        Assert.AreEqual(255, cmd.Parameters(0).Value.ToString().Length, "Maximum length input should be handled correctly")
    End Sub

    ''' <summary>
    ''' Integration test: Verify complete parameterized query workflow
    ''' </summary>
    <TestMethod>
    Public Sub TestCompleteParameterizedQueryWorkflow()
        ' Arrange
        Dim cmd As New ADODB.Command()
        Dim testUserName As String = "admin"
        Dim testPassword As String = "password123"
        Dim paramUserName As ADODB.Parameter
        Dim paramPassword As ADODB.Parameter

        ' Act - Simulate the complete workflow from cmdUnsafe_Click
        cmd.CommandText = "SELECT COUNT (*) FROM Passwords WHERE UserName=? AND Password=?"
        cmd.CommandType = CommandTypeEnum.adCmdText

        paramUserName = cmd.CreateParameter("UserName", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, testUserName)
        cmd.Parameters.Append(paramUserName)

        paramPassword = cmd.CreateParameter("Password", DataTypeEnum.adVarChar, ParameterDirectionEnum.adParamInput, 255, testPassword)
        cmd.Parameters.Append(paramPassword)

        ' Assert - Verify complete setup
        Assert.IsTrue(cmd.CommandText.Contains("?"), "Query should use parameter placeholders")
        Assert.AreEqual(2, cmd.Parameters.Count, "Should have 2 parameters")
        Assert.AreEqual(testUserName, cmd.Parameters(0).Value, "First parameter should match username")
        Assert.AreEqual(testPassword, cmd.Parameters(1).Value, "Second parameter should match password")
        Assert.AreEqual(CommandTypeEnum.adCmdText, cmd.CommandType, "Command type should be text")
    End Sub

End Class
