/**
 * @name cups-d47f6aec436e0e9df6554436e391471097686ecc-read_cupsd_conf
 * @id cpp/cups/d47f6aec436e0e9df6554436e391471097686ecc/read-cupsd-conf
 * @description cups-d47f6aec436e0e9df6554436e391471097686ecc-scheduler/conf.c-read_cupsd_conf CVE-2018-4180
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Printcap"
		and not target_0.getValue()="PassEnv"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="PrintcapFormat"
		and not target_1.getValue()="Printcap"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="RemoteRoot"
		and not target_2.getValue()="PrintcapFormat"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="RequestRoot"
		and not target_3.getValue()="RemoteRoot"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, StringLiteral target_4) {
		target_4.getValue()="ServerBin"
		and not target_4.getValue()="RequestRoot"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Function func, StringLiteral target_5) {
		target_5.getValue()="ServerCertificate"
		and not target_5.getValue()="ServerBin"
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Function func, StringLiteral target_6) {
		target_6.getValue()="ServerKey"
		and not target_6.getValue()="ServerCertificate"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, StringLiteral target_7) {
		target_7.getValue()="ServerKeychain"
		and not target_7.getValue()="ServerKey"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, StringLiteral target_8) {
		target_8.getValue()="ServerRoot"
		and not target_8.getValue()="ServerKeychain"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Function func, StringLiteral target_9) {
		target_9.getValue()="SMBConfigFile"
		and not target_9.getValue()="ServerRoot"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, StringLiteral target_10) {
		target_10.getValue()="StateDir"
		and not target_10.getValue()="SetEnv"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, StringLiteral target_11) {
		target_11.getValue()="SystemGroup"
		and not target_11.getValue()="SMBConfigFile"
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, StringLiteral target_12) {
		target_12.getValue()="SystemGroupAuthKey"
		and not target_12.getValue()="StateDir"
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, StringLiteral target_13) {
		target_13.getValue()="TempDir"
		and not target_13.getValue()="SystemGroup"
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, StringLiteral target_14) {
		target_14.getValue()="User"
		and not target_14.getValue()="SystemGroupAuthKey"
		and target_14.getEnclosingFunction() = func
}

predicate func_15(BlockStmt target_70, Function func) {
	exists(LogicalOrExpr target_15 |
		target_15.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_15.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_15.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_15.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_15.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_15.getAnOperand() instanceof NotExpr
		and target_15.getParent().(IfStmt).getThen()=target_70
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Function func, FunctionCall target_16) {
		target_16.getTarget().hasName("strerror")
		and target_16.getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Variable vline_2928, Variable vvalue_2932, BlockStmt target_71, LogicalAndExpr target_17) {
		target_17.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_17.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_17.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="<Location"
		and target_17.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_17.getParent().(IfStmt).getThen()=target_71
}

predicate func_18(Variable vline_2928, Variable vvalue_2932, BlockStmt target_72, LogicalAndExpr target_18) {
		target_18.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_18.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_18.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="<Policy"
		and target_18.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_18.getParent().(IfStmt).getThen()=target_72
}

predicate func_19(Variable vline_2928, Variable vvalue_2932, BlockStmt target_73, LogicalAndExpr target_19) {
		target_19.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_19.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_19.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="FaxRetryInterval"
		and target_19.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_19.getParent().(IfStmt).getThen()=target_73
}

predicate func_20(Variable vline_2928, Variable vvalue_2932, BlockStmt target_74, LogicalAndExpr target_20) {
		target_20.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_20.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_20.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="FaxRetryLimit"
		and target_20.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_20.getParent().(IfStmt).getThen()=target_74
}

predicate func_21(Variable vline_2928, BlockStmt target_75, NotExpr target_21) {
		target_21.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_21.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_21.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSLOptions"
		and target_21.getParent().(IfStmt).getThen()=target_75
}

predicate func_22(Variable vline_2928, Variable vvalue_2932, BlockStmt target_76, LogicalAndExpr target_22) {
		target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Port"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Listen"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSLPort"
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_22.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SSLListen"
		and target_22.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_22.getParent().(IfStmt).getThen()=target_76
}

predicate func_23(Variable vline_2928, BlockStmt target_77, LogicalOrExpr target_23) {
		target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="BrowseProtocols"
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_23.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="BrowseLocalProtocols"
		and target_23.getParent().(IfStmt).getThen()=target_77
}

predicate func_24(Variable vline_2928, Variable vvalue_2932, BlockStmt target_78, LogicalAndExpr target_24) {
		target_24.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_24.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_24.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DefaultAuthType"
		and target_24.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_24.getParent().(IfStmt).getThen()=target_78
}

predicate func_25(Variable vline_2928, BlockStmt target_79, NotExpr target_25) {
		target_25.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_25.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_25.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DefaultEncryption"
		and target_25.getParent().(IfStmt).getThen()=target_79
}

predicate func_26(Variable vline_2928, Variable vvalue_2932, BlockStmt target_80, LogicalAndExpr target_26) {
		target_26.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_26.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_26.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="HostNameLookups"
		and target_26.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_26.getParent().(IfStmt).getThen()=target_80
}

predicate func_27(Variable vline_2928, Variable vvalue_2932, BlockStmt target_81, LogicalAndExpr target_27) {
		target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_27.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="AccessLogLevel"
		and target_27.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_27.getParent().(IfStmt).getThen()=target_81
}

predicate func_28(Variable vline_2928, Variable vvalue_2932, BlockStmt target_82, LogicalAndExpr target_28) {
		target_28.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_28.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_28.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="LogLevel"
		and target_28.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_28.getParent().(IfStmt).getThen()=target_82
}

predicate func_29(Variable vline_2928, Variable vvalue_2932, BlockStmt target_83, LogicalAndExpr target_29) {
		target_29.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_29.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_29.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="LogTimeFormat"
		and target_29.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_29.getParent().(IfStmt).getThen()=target_83
}

predicate func_30(Variable vline_2928, Variable vvalue_2932, BlockStmt target_84, LogicalAndExpr target_30) {
		target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_30.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ServerTokens"
		and target_30.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_30.getParent().(IfStmt).getThen()=target_84
}

predicate func_31(Variable vvalue_2932, PointerDereferenceExpr target_31) {
		target_31.getOperand().(VariableAccess).getTarget()=vvalue_2932
}

predicate func_32(Variable vvalue_2932, Variable vvaluelen_2934, IfStmt target_32) {
		target_32.getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_32.getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_32.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_32.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvaluelen_2934
}

predicate func_33(Variable vline_2928, Variable vvalue_2932, BlockStmt target_85, LogicalAndExpr target_33) {
		target_33.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_33.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_33.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ServerAlias"
		and target_33.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_33.getParent().(IfStmt).getThen()=target_85
}

/*predicate func_34(Variable vline_2928, NotExpr target_34) {
		target_34.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_34.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_34.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_35(Variable vline_2928, NotExpr target_35) {
		target_35.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_35.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_35.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_36(Variable vline_2928, NotExpr target_36) {
		target_36.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_36.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_36.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_37(Variable vline_2928, NotExpr target_37) {
		target_37.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_37.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_37.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_38(Variable vline_2928, NotExpr target_38) {
		target_38.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_38.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_38.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_39(Variable vline_2928, NotExpr target_39) {
		target_39.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_39.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_39.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_40(Variable vline_2928, NotExpr target_40) {
		target_40.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_40.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_40.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_41(Variable vline_2928, NotExpr target_41) {
		target_41.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_41.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_41.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_42(Variable vline_2928, NotExpr target_42) {
		target_42.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_42.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_42.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_43(Variable vline_2928, NotExpr target_43) {
		target_43.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_43.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_43.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_44(Variable vline_2928, NotExpr target_44) {
		target_44.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_44.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_44.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_45(Variable vline_2928, NotExpr target_45) {
		target_45.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_45.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_45.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_46(Variable vline_2928, NotExpr target_46) {
		target_46.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_46.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_46.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
/*predicate func_47(Variable vline_2928, NotExpr target_47) {
		target_47.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_47.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_47.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
}

*/
predicate func_48(Variable vline_2928, BlockStmt target_86, NotExpr target_48) {
		target_48.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_48.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_48.getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_48.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_48.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_86
}

predicate func_49(Variable vline_2928, Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, Variable vcupsd_vars, LogicalAndExpr target_87, ExprStmt target_49) {
		target_49.getExpr().(FunctionCall).getTarget().hasName("parse_variable")
		and target_49.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vConfigurationFile
		and target_49.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlinenum_2927
		and target_49.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_2928
		and target_49.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvalue_2932
		and target_49.getExpr().(FunctionCall).getArgument(4).(DivExpr).getValue()="55"
		and target_49.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vcupsd_vars
		and target_49.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_87
}

predicate func_50(Variable vline_2928, Variable vvalue_2932, BlockStmt target_70, NotExpr target_50) {
		target_50.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_50.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_50.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="PassEnv"
		and target_50.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_50.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_70
}

predicate func_51(Variable vline_2928, Variable vvalue_2932, BlockStmt target_88, NotExpr target_51) {
		target_51.getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_51.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_51.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SetEnv"
		and target_51.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_51.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_88
}

predicate func_52(Variable vvalue_2932, Variable vvaluelen_2934, BlockStmt target_52) {
		target_52.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvaluelen_2934
		and target_52.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_52.getStmt(0).(ForStmt).getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_52.getStmt(0).(ForStmt).getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_52.getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvaluelen_2934
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("_cups_isspace")
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="44"
		and target_52.getStmt(0).(ForStmt).getStmt().(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_52.getStmt(1).(LabelStmt).toString() = "label ...:"
}

predicate func_53(Variable vvalue_2932, Variable vvaluelen_2934, BlockStmt target_53) {
		target_53.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vvalue_2932
		and target_53.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vvaluelen_2934
		and target_53.getStmt(0).(ForStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_53.getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_53.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_isspace")
		and target_53.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_53.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="44"
		and target_53.getStmt(0).(ForStmt).getStmt().(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_53.getStmt(1).(LabelStmt).toString() = "label ...:"
}

predicate func_55(Function func, DeclStmt target_55) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_55
}

predicate func_56(Function func, DeclStmt target_56) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_56
}

predicate func_57(Variable vline_2928, Variable vvalue_2932, BlockStmt target_89, LogicalAndExpr target_57) {
		target_57.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_57.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_2928
		and target_57.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Include"
		and target_57.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_57.getParent().(IfStmt).getThen()=target_89
}

predicate func_58(Variable vvalue_2932, Variable vincname_2938, Variable vServerRoot, LogicalAndExpr target_57, IfStmt target_58) {
		target_58.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_58.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_58.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_58.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cups_strlcpy")
		and target_58.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincname_2938
		and target_58.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_2932
		and target_58.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="1024"
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincname_2938
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s/%s"
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vServerRoot
		and target_58.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_2932
		and target_58.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
}

predicate func_59(Variable vincfile_2937, Variable vincname_2938, LogicalAndExpr target_57, IfStmt target_59) {
		target_59.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vincfile_2937
		and target_59.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cupsFileOpen")
		and target_59.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincname_2938
		and target_59.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="rb"
		and target_59.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_59.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_59.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unable to include config file \"%s\" - %s"
		and target_59.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vincname_2938
		and target_59.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof FunctionCall
		and target_59.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("read_cupsd_conf")
		and target_59.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincfile_2937
		and target_59.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsFileClose")
		and target_59.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincfile_2937
		and target_59.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_57
}

/*predicate func_60(Variable vincfile_2937, EqualityOperation target_90, ExprStmt target_60) {
		target_60.getExpr().(FunctionCall).getTarget().hasName("read_cupsd_conf")
		and target_60.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincfile_2937
		and target_60.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_90
}

*/
/*predicate func_61(Variable vincfile_2937, EqualityOperation target_90, ExprStmt target_61) {
		target_61.getExpr().(FunctionCall).getTarget().hasName("cupsFileClose")
		and target_61.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vincfile_2937
		and target_61.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_90
}

*/
predicate func_62(Variable vvalue_2932, BlockStmt target_70, LogicalAndExpr target_62) {
		target_62.getAnOperand() instanceof NotExpr
		and target_62.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_62.getParent().(IfStmt).getThen()=target_70
}

predicate func_63(Variable vvalue_2932, LogicalAndExpr target_62, ForStmt target_63) {
		target_63.getCondition() instanceof PointerDereferenceExpr
		and target_63.getStmt().(BlockStmt).getStmt(0) instanceof BlockStmt
		and target_63.getStmt().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_63.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetEnv")
		and target_63.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_63.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_63.getStmt().(BlockStmt).getStmt(3) instanceof BlockStmt
		and target_63.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_62
}

/*predicate func_64(Variable vvalue_2932, ExprStmt target_64) {
		target_64.getExpr().(FunctionCall).getTarget().hasName("cupsdSetEnv")
		and target_64.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_64.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

*/
predicate func_65(Variable vline_2928, Variable vlinenum_2927, Variable vvalue_2932, Variable vvalueptr_2933, Variable vvaluelen_2934, Variable vConfigurationFile, Variable vServerAlias, Variable vCupsFilesFile, LogicalAndExpr target_30, IfStmt target_65) {
		target_65.getCondition() instanceof LogicalAndExpr
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vServerAlias
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vServerAlias
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cupsArrayNew")
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_2932
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vvaluelen_2934
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdAddAlias")
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vServerAlias
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_2932
		and target_65.getThen().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(3).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_65.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_65.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvalueptr_2933
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2932
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ForStmt).getStmt().(EmptyStmt).toString() = ";"
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetEnv")
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Missing value for SetEnv directive on line %d of %s."
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_65.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vConfigurationFile
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Please move \"%s%s%s\" on line %d of %s to the %s file; this will become an error in a future release."
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_2928
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vlinenum_2927
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vConfigurationFile
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vCupsFilesFile
		and target_65.getElse().(IfStmt).getElse().(IfStmt).getElse() instanceof ExprStmt
		and target_65.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_30
}

/*predicate func_66(Variable vvalue_2932, Variable vvalueptr_2933, LogicalAndExpr target_87, ForStmt target_66) {
		target_66.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvalueptr_2933
		and target_66.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2932
		and target_66.getCondition().(LogicalAndExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_66.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_66.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_66.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_66.getStmt().(EmptyStmt).toString() = ";"
		and target_66.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_87
}

*/
/*predicate func_67(Variable vlinenum_2927, Variable vvalue_2932, Variable vvalueptr_2933, Variable vConfigurationFile, LogicalAndExpr target_87, IfStmt target_67) {
		target_67.getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_67.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_67.getThen().(BlockStmt).getStmt(0).(WhileStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_67.getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetEnv")
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_67.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalueptr_2933
		and target_67.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_67.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Missing value for SetEnv directive on line %d of %s."
		and target_67.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_67.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vConfigurationFile
		and target_67.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_87
}

*/
/*predicate func_68(Variable vvalueptr_2933, PointerDereferenceExpr target_91, WhileStmt target_68) {
		target_68.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__ctype_b_loc")
		and target_68.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_68.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_68.getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vvalueptr_2933
		and target_68.getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_68.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_91
}

*/
/*predicate func_69(Variable vvalue_2932, Variable vvalueptr_2933, PointerDereferenceExpr target_91, ExprStmt target_69) {
		target_69.getExpr().(FunctionCall).getTarget().hasName("cupsdSetEnv")
		and target_69.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_69.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalueptr_2933
		and target_69.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_91
}

*/
predicate func_70(BlockStmt target_70) {
		target_70.getStmt(0) instanceof ForStmt
}

predicate func_71(Variable vlinenum_2927, Variable vvalue_2932, BlockStmt target_71) {
		target_71.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlinenum_2927
		and target_71.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_location")
		and target_71.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_2932
		and target_71.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_71.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlinenum_2927
		and target_71.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_71.getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_72(Variable vlinenum_2927, Variable vvalue_2932, BlockStmt target_72) {
		target_72.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlinenum_2927
		and target_72.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_policy")
		and target_72.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_2932
		and target_72.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_72.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlinenum_2927
		and target_72.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_72.getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_73(Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, BlockStmt target_73) {
		target_73.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_73.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_73.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_73.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="FaxRetryInterval is deprecated; use JobRetryInterval on line %d of %s."
		and target_73.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_73.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vConfigurationFile
}

predicate func_74(Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, BlockStmt target_74) {
		target_74.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("atoi")
		and target_74.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_74.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_74.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="FaxRetryLimit is deprecated; use JobRetryLimit on line %d of %s."
		and target_74.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlinenum_2927
		and target_74.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vConfigurationFile
}

predicate func_75(Variable vvalue_2932, BlockStmt target_75) {
		target_75.getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vvalue_2932
		and target_75.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_2932
		and target_75.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_httpTLSSetOptions")
}

predicate func_76(Variable vline_2928, Variable vlinenum_2927, Variable vvalue_2932, BlockStmt target_76) {
		target_76.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_address")
		and target_76.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_76.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="631"
		and target_76.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_76.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Bad %s address %s at line %d."
		and target_76.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_2928
		and target_76.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvalue_2932
		and target_76.getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vlinenum_2927
}

predicate func_77(Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, BlockStmt target_77) {
		target_77.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_77.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_77.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unknown browse protocol \"%s\" on line %d of %s."
		and target_77.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_2932
		and target_77.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlinenum_2927
		and target_77.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vConfigurationFile
}

predicate func_78(Variable vvalue_2932, BlockStmt target_78) {
		target_78.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_78.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_78.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="none"
		and target_78.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="basic"
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="negotiate"
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_78.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
}

predicate func_79(Variable vvalue_2932, BlockStmt target_79) {
		target_79.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vvalue_2932
		and target_79.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_79.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_79.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="never"
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="required"
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ifrequested"
		and target_79.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
}

predicate func_80(Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, BlockStmt target_80) {
		target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="off"
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="no"
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="false"
		and target_80.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="true"
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="double"
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unknown HostNameLookups %s on line %d of %s."
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_2932
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlinenum_2927
		and target_80.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vConfigurationFile
}

predicate func_81(Variable vvalue_2932, BlockStmt target_81) {
		target_81.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_81.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_81.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="all"
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="actions"
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="config"
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_81.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
}

predicate func_82(Variable vvalue_2932, BlockStmt target_82) {
		target_82.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_82.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_82.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="debug2"
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="debug"
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="info"
		and target_82.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
}

predicate func_83(Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, BlockStmt target_83) {
		target_83.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_83.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_83.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="standard"
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="usecs"
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unknown LogTimeFormat %s on line %d of %s."
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_2932
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlinenum_2927
		and target_83.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vConfigurationFile
}

predicate func_84(Variable vvalue_2932, BlockStmt target_84) {
		target_84.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("uname")
		and target_84.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_84.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_84.getStmt(2).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ProductOnly"
		and target_84.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetString")
		and target_84.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CUPS IPP"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Major"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetStringf")
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CUPS/%d IPP/2"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_2932
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Minor"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetStringf")
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="CUPS/%d.%d IPP/2.1"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="3"
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_cups_strcasecmp")
		and target_84.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdSetString")
}

predicate func_85(Variable vServerAlias, BlockStmt target_85) {
		target_85.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vServerAlias
		and target_85.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vServerAlias
		and target_85.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cupsArrayNew")
		and target_85.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_85.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_86(Variable vline_2928, Variable vlinenum_2927, Variable vvalue_2932, Variable vConfigurationFile, Variable vCupsFilesFile, BlockStmt target_86) {
		target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cupsdLogMessage")
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Please move \"%s%s%s\" on line %d of %s to the %s file; this will become an error in a future release."
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vline_2928
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vvalue_2932
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()=" "
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vvalue_2932
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vvalue_2932
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vlinenum_2927
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vConfigurationFile
		and target_86.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vCupsFilesFile
}

predicate func_87(Variable vvalue_2932, LogicalAndExpr target_87) {
		target_87.getAnOperand() instanceof NotExpr
		and target_87.getAnOperand().(VariableAccess).getTarget()=vvalue_2932
}

predicate func_88(BlockStmt target_88) {
		target_88.getStmt(0) instanceof ForStmt
		and target_88.getStmt(1) instanceof IfStmt
}

predicate func_89(BlockStmt target_89) {
		target_89.getStmt(0) instanceof IfStmt
		and target_89.getStmt(1) instanceof IfStmt
}

predicate func_90(EqualityOperation target_90) {
		target_90.getAnOperand() instanceof AssignExpr
		and target_90.getAnOperand() instanceof Literal
}

predicate func_91(Variable vvalueptr_2933, PointerDereferenceExpr target_91) {
		target_91.getOperand().(VariableAccess).getTarget()=vvalueptr_2933
}

from Function func, Variable vline_2928, Variable vlinenum_2927, Variable vvalue_2932, Variable vvalueptr_2933, Variable vvaluelen_2934, Variable vincfile_2937, Variable vincname_2938, Variable vServerRoot, Variable vConfigurationFile, Variable vServerAlias, Variable vCupsFilesFile, Variable vcupsd_vars, StringLiteral target_0, StringLiteral target_1, StringLiteral target_2, StringLiteral target_3, StringLiteral target_4, StringLiteral target_5, StringLiteral target_6, StringLiteral target_7, StringLiteral target_8, StringLiteral target_9, StringLiteral target_10, StringLiteral target_11, StringLiteral target_12, StringLiteral target_13, StringLiteral target_14, FunctionCall target_16, LogicalAndExpr target_17, LogicalAndExpr target_18, LogicalAndExpr target_19, LogicalAndExpr target_20, NotExpr target_21, LogicalAndExpr target_22, LogicalOrExpr target_23, LogicalAndExpr target_24, NotExpr target_25, LogicalAndExpr target_26, LogicalAndExpr target_27, LogicalAndExpr target_28, LogicalAndExpr target_29, LogicalAndExpr target_30, PointerDereferenceExpr target_31, IfStmt target_32, LogicalAndExpr target_33, NotExpr target_48, ExprStmt target_49, NotExpr target_50, NotExpr target_51, BlockStmt target_52, BlockStmt target_53, DeclStmt target_55, DeclStmt target_56, LogicalAndExpr target_57, IfStmt target_58, IfStmt target_59, LogicalAndExpr target_62, ForStmt target_63, IfStmt target_65, BlockStmt target_70, BlockStmt target_71, BlockStmt target_72, BlockStmt target_73, BlockStmt target_74, BlockStmt target_75, BlockStmt target_76, BlockStmt target_77, BlockStmt target_78, BlockStmt target_79, BlockStmt target_80, BlockStmt target_81, BlockStmt target_82, BlockStmt target_83, BlockStmt target_84, BlockStmt target_85, BlockStmt target_86, LogicalAndExpr target_87, BlockStmt target_88, BlockStmt target_89, EqualityOperation target_90, PointerDereferenceExpr target_91
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(func, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and not func_15(target_70, func)
and func_16(func, target_16)
and func_17(vline_2928, vvalue_2932, target_71, target_17)
and func_18(vline_2928, vvalue_2932, target_72, target_18)
and func_19(vline_2928, vvalue_2932, target_73, target_19)
and func_20(vline_2928, vvalue_2932, target_74, target_20)
and func_21(vline_2928, target_75, target_21)
and func_22(vline_2928, vvalue_2932, target_76, target_22)
and func_23(vline_2928, target_77, target_23)
and func_24(vline_2928, vvalue_2932, target_78, target_24)
and func_25(vline_2928, target_79, target_25)
and func_26(vline_2928, vvalue_2932, target_80, target_26)
and func_27(vline_2928, vvalue_2932, target_81, target_27)
and func_28(vline_2928, vvalue_2932, target_82, target_28)
and func_29(vline_2928, vvalue_2932, target_83, target_29)
and func_30(vline_2928, vvalue_2932, target_84, target_30)
and func_31(vvalue_2932, target_31)
and func_32(vvalue_2932, vvaluelen_2934, target_32)
and func_33(vline_2928, vvalue_2932, target_85, target_33)
and func_48(vline_2928, target_86, target_48)
and func_49(vline_2928, vlinenum_2927, vvalue_2932, vConfigurationFile, vcupsd_vars, target_87, target_49)
and func_50(vline_2928, vvalue_2932, target_70, target_50)
and func_51(vline_2928, vvalue_2932, target_88, target_51)
and func_52(vvalue_2932, vvaluelen_2934, target_52)
and func_53(vvalue_2932, vvaluelen_2934, target_53)
and func_55(func, target_55)
and func_56(func, target_56)
and func_57(vline_2928, vvalue_2932, target_89, target_57)
and func_58(vvalue_2932, vincname_2938, vServerRoot, target_57, target_58)
and func_59(vincfile_2937, vincname_2938, target_57, target_59)
and func_62(vvalue_2932, target_70, target_62)
and func_63(vvalue_2932, target_62, target_63)
and func_65(vline_2928, vlinenum_2927, vvalue_2932, vvalueptr_2933, vvaluelen_2934, vConfigurationFile, vServerAlias, vCupsFilesFile, target_30, target_65)
and func_70(target_70)
and func_71(vlinenum_2927, vvalue_2932, target_71)
and func_72(vlinenum_2927, vvalue_2932, target_72)
and func_73(vlinenum_2927, vvalue_2932, vConfigurationFile, target_73)
and func_74(vlinenum_2927, vvalue_2932, vConfigurationFile, target_74)
and func_75(vvalue_2932, target_75)
and func_76(vline_2928, vlinenum_2927, vvalue_2932, target_76)
and func_77(vlinenum_2927, vvalue_2932, vConfigurationFile, target_77)
and func_78(vvalue_2932, target_78)
and func_79(vvalue_2932, target_79)
and func_80(vlinenum_2927, vvalue_2932, vConfigurationFile, target_80)
and func_81(vvalue_2932, target_81)
and func_82(vvalue_2932, target_82)
and func_83(vlinenum_2927, vvalue_2932, vConfigurationFile, target_83)
and func_84(vvalue_2932, target_84)
and func_85(vServerAlias, target_85)
and func_86(vline_2928, vlinenum_2927, vvalue_2932, vConfigurationFile, vCupsFilesFile, target_86)
and func_87(vvalue_2932, target_87)
and func_88(target_88)
and func_89(target_89)
and func_90(target_90)
and func_91(vvalueptr_2933, target_91)
and vline_2928.getType().hasName("char[2048]")
and vlinenum_2927.getType().hasName("int")
and vvalue_2932.getType().hasName("char *")
and vvalueptr_2933.getType().hasName("char *")
and vvaluelen_2934.getType().hasName("int")
and vincfile_2937.getType().hasName("cups_file_t *")
and vincname_2938.getType().hasName("char[1024]")
and vServerRoot.getType().hasName("char *")
and vConfigurationFile.getType().hasName("char *")
and vServerAlias.getType().hasName("cups_array_t *")
and vCupsFilesFile.getType().hasName("char *")
and vcupsd_vars.getType() instanceof ArrayType
and vline_2928.getParentScope+() = func
and vlinenum_2927.getParentScope+() = func
and vvalue_2932.getParentScope+() = func
and vvalueptr_2933.getParentScope+() = func
and vvaluelen_2934.getParentScope+() = func
and vincfile_2937.getParentScope+() = func
and vincname_2938.getParentScope+() = func
and not vServerRoot.getParentScope+() = func
and not vConfigurationFile.getParentScope+() = func
and not vServerAlias.getParentScope+() = func
and not vCupsFilesFile.getParentScope+() = func
and not vcupsd_vars.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
