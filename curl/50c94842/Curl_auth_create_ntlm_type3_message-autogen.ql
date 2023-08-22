/**
 * @name curl-50c94842-Curl_auth_create_ntlm_type3_message
 * @id cpp/curl/50c94842/Curl-auth-create-ntlm-type3-message
 * @description curl-50c94842-lib/vauth/ntlm.c-Curl_auth_create_ntlm_type3_message CVE-2019-3822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_519, Variable vntresplen_525, BlockStmt target_9, ExprStmt target_10, AddressOfExpr target_11, BitwiseAndExpr target_12, ExprStmt target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vntresplen_525
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_519
		and target_0.getLesserOperand().(SizeofExprOperator).getValue()="1024"
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_12.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_493, RelationalOperation target_8, ExprStmt target_13, ExprStmt target_14) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_493
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="incoming NTLM message too big"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(RelationalOperation target_8, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(RelationalOperation target_8, Function func, DoStmt target_3) {
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vsize_519, Variable vntlmbuf_520, Variable vntresplen_525, Variable vptr_ntresp_527, RelationalOperation target_8, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vntlmbuf_520
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsize_519
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vptr_ntresp_527
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vntresplen_525
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_5(Variable vsize_519, Variable vntresplen_525, RelationalOperation target_8, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsize_519
		and target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vntresplen_525
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_6(Variable vsize_519, BlockStmt target_9, VariableAccess target_6) {
		target_6.getTarget()=vsize_519
		and target_6.getParent().(LTExpr).getGreaterOperand() instanceof SubExpr
		and target_6.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Variable vntresplen_525, VariableAccess target_7) {
		target_7.getTarget()=vntresplen_525
}

predicate func_8(Variable vsize_519, Variable vntresplen_525, BlockStmt target_9, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vsize_519
		and target_8.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_8.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vntresplen_525
		and target_8.getParent().(IfStmt).getThen()=target_9
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0) instanceof DoStmt
		and target_9.getStmt(1) instanceof ExprStmt
		and target_9.getStmt(2) instanceof ExprStmt
}

predicate func_10(Variable vsize_519, ExprStmt target_10) {
		target_10.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsize_519
		and target_10.getExpr().(AssignAddExpr).getRValue().(HexLiteral).getValue()="24"
}

predicate func_11(Variable vsize_519, Variable vntlmbuf_520, AddressOfExpr target_11) {
		target_11.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vntlmbuf_520
		and target_11.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsize_519
}

predicate func_12(Variable vntresplen_525, BitwiseAndExpr target_12) {
		target_12.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vntresplen_525
		and target_12.getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_12.getRightOperand().(Literal).getValue()="255"
}

predicate func_13(Parameter vdata_493, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("CURLcode")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_ntlm_core_mk_lm_hash")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_493
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("unsigned char[24]")
}

predicate func_14(Parameter vdata_493, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_493
		and target_14.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="user + domain + host name too big"
}

from Function func, Parameter vdata_493, Variable vsize_519, Variable vntlmbuf_520, Variable vntresplen_525, Variable vptr_ntresp_527, DoStmt target_3, ExprStmt target_4, ExprStmt target_5, VariableAccess target_6, VariableAccess target_7, RelationalOperation target_8, BlockStmt target_9, ExprStmt target_10, AddressOfExpr target_11, BitwiseAndExpr target_12, ExprStmt target_13, ExprStmt target_14
where
not func_0(vsize_519, vntresplen_525, target_9, target_10, target_11, target_12, target_4)
and not func_1(vdata_493, target_8, target_13, target_14)
and not func_2(target_8, func)
and func_3(target_8, func, target_3)
and func_4(vsize_519, vntlmbuf_520, vntresplen_525, vptr_ntresp_527, target_8, target_4)
and func_5(vsize_519, vntresplen_525, target_8, target_5)
and func_6(vsize_519, target_9, target_6)
and func_7(vntresplen_525, target_7)
and func_8(vsize_519, vntresplen_525, target_9, target_8)
and func_9(target_9)
and func_10(vsize_519, target_10)
and func_11(vsize_519, vntlmbuf_520, target_11)
and func_12(vntresplen_525, target_12)
and func_13(vdata_493, target_13)
and func_14(vdata_493, target_14)
and vdata_493.getType().hasName("Curl_easy *")
and vsize_519.getType().hasName("size_t")
and vntlmbuf_520.getType().hasName("unsigned char[1024]")
and vntresplen_525.getType().hasName("unsigned int")
and vptr_ntresp_527.getType().hasName("unsigned char *")
and vdata_493.getFunction() = func
and vsize_519.(LocalVariable).getFunction() = func
and vntlmbuf_520.(LocalVariable).getFunction() = func
and vntresplen_525.(LocalVariable).getFunction() = func
and vptr_ntresp_527.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
