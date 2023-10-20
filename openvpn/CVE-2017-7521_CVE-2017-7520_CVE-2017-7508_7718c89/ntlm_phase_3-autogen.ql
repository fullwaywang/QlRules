/**
 * @name openvpn-7718c8984f-ntlm_phase_3
 * @id cpp/openvpn/7718c8984f/ntlm-phase-3
 * @description openvpn-7718c8984f-src/openvpn/ntlm.c-ntlm_phase_3 CVE-2017-7508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vbuf2_198, Initializer target_1) {
		target_1.getExpr().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf2_198
		and target_1.getExpr().(PointerArithmeticOperation).getAnOperand() instanceof ArrayExpr
}

predicate func_2(Variable vtib_len_271, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtib_len_271
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="128"
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Variable vtib_ptr_304, Variable vbuf2_198, ExprStmt target_7) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtib_ptr_304
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf2_198
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vbuf2_198, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vbuf2_198
		and target_4.getArrayOffset().(HexLiteral).getValue()="44"
}

predicate func_5(Variable vbuf2_198, ExprStmt target_8, VariableAccess target_5) {
		target_5.getTarget()=vbuf2_198
		and target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getLocation())
}

predicate func_6(Variable vtib_len_271, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtib_len_271
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="96"
}

predicate func_7(Variable vtib_len_271, Variable vtib_ptr_304, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(HexLiteral).getValue()="28"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtib_ptr_304
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtib_len_271
}

predicate func_8(Variable vtib_len_271, Variable vbuf2_198, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtib_len_271
		and target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf2_198
		and target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(HexLiteral).getValue()="40"
}

from Function func, Variable vtib_len_271, Variable vtib_ptr_304, Variable vbuf2_198, Initializer target_1, ArrayExpr target_4, VariableAccess target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
func_1(vbuf2_198, target_1)
and not func_2(vtib_len_271, target_6, target_7)
and not func_3(vtib_ptr_304, vbuf2_198, target_7)
and func_4(vbuf2_198, target_4)
and func_5(vbuf2_198, target_8, target_5)
and func_6(vtib_len_271, target_6)
and func_7(vtib_len_271, vtib_ptr_304, target_7)
and func_8(vtib_len_271, vbuf2_198, target_8)
and vtib_len_271.getType().hasName("int")
and vtib_ptr_304.getType().hasName("char *")
and vbuf2_198.getType().hasName("char[128]")
and vtib_len_271.getParentScope+() = func
and vtib_ptr_304.getParentScope+() = func
and vbuf2_198.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
