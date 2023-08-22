/**
 * @name curl-358b2b131ad6c095696f20dcfa62b8305263f898-tftp_send_first
 * @id cpp/curl/358b2b131ad6c095696f20dcfa62b8305263f898/tftp-send-first
 * @description curl-358b2b131ad6c095696f20dcfa62b8305263f898-lib/tftp.c-tftp_send_first CVE-2017-1000100
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstate_448, Variable vmode_452, Variable vfilename_453, Variable vdata_455, VariableAccess target_1, PointerFieldAccess target_2, PointerArithmeticOperation target_3, ExprStmt target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7, NotExpr target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilename_453
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="blksize"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_448
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmode_452
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_455
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="TFTP file name too long\n"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vevent_448, VariableAccess target_1) {
		target_1.getTarget()=vevent_448
}

predicate func_2(Parameter vstate_448, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="conn"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_448
}

predicate func_3(Parameter vstate_448, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="spacket"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_448
		and target_3.getAnOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vmode_452, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmode_452
		and target_4.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="netascii"
}

predicate func_5(Parameter vstate_448, Variable vmode_452, Variable vfilename_453, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("curl_msnprintf")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="spacket"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_448
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="blksize"
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_448
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s%c%s%c"
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfilename_453
		and target_5.getExpr().(FunctionCall).getArgument(4).(CharLiteral).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmode_452
		and target_5.getExpr().(FunctionCall).getArgument(6).(CharLiteral).getValue()="0"
}

predicate func_6(Variable vfilename_453, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vfilename_453
}

predicate func_7(Variable vfilename_453, Variable vdata_455, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("CURLcode")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_urldecode")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_455
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="path"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfilename_453
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_8(Variable vdata_455, NotExpr target_8) {
		target_8.getOperand().(ValueFieldAccess).getTarget().getName()="tftp_no_options"
		and target_8.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_8.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_455
}

from Function func, Parameter vevent_448, Parameter vstate_448, Variable vmode_452, Variable vfilename_453, Variable vdata_455, VariableAccess target_1, PointerFieldAccess target_2, PointerArithmeticOperation target_3, ExprStmt target_4, ExprStmt target_5, AddressOfExpr target_6, ExprStmt target_7, NotExpr target_8
where
not func_0(vstate_448, vmode_452, vfilename_453, vdata_455, target_1, target_2, target_3, target_4, target_5, target_6, target_7, target_8)
and func_1(vevent_448, target_1)
and func_2(vstate_448, target_2)
and func_3(vstate_448, target_3)
and func_4(vmode_452, target_4)
and func_5(vstate_448, vmode_452, vfilename_453, target_5)
and func_6(vfilename_453, target_6)
and func_7(vfilename_453, vdata_455, target_7)
and func_8(vdata_455, target_8)
and vevent_448.getType().hasName("tftp_event_t")
and vstate_448.getType().hasName("tftp_state_data_t *")
and vmode_452.getType().hasName("const char *")
and vfilename_453.getType().hasName("char *")
and vdata_455.getType().hasName("Curl_easy *")
and vevent_448.getFunction() = func
and vstate_448.getFunction() = func
and vmode_452.(LocalVariable).getFunction() = func
and vfilename_453.(LocalVariable).getFunction() = func
and vdata_455.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
