/**
 * @name curl-b780b30d-ntlm_decode_type2_target
 * @id cpp/curl/b780b30d/ntlm-decode-type2-target
 * @description curl-b780b30d-lib/vauth/ntlm.c-ntlm_decode_type2_target CVE-2018-16890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_171, Variable vtarget_info_offset_175, BlockStmt target_2, RelationalOperation target_3, ExprStmt target_5, LogicalOrExpr target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_171
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsize_171, Variable vtarget_info_len_174, Variable vtarget_info_offset_175, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtarget_info_len_174
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vsize_171
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_infof")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NTLM handshake failure (bad type-2 message). Target Info Offset Len is set incorrect by the peer\n"
}

predicate func_3(Parameter vsize_171, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vsize_171
		and target_3.getLesserOperand().(Literal).getValue()="48"
}

predicate func_5(Variable vtarget_info_offset_175, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("Curl_read32_le")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="44"
}

predicate func_6(Variable vtarget_info_offset_175, LogicalOrExpr target_6) {
		target_6.getAnOperand() instanceof RelationalOperation
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtarget_info_offset_175
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="48"
}

from Function func, Parameter vsize_171, Variable vtarget_info_len_174, Variable vtarget_info_offset_175, RelationalOperation target_1, BlockStmt target_2, RelationalOperation target_3, ExprStmt target_5, LogicalOrExpr target_6
where
not func_0(vsize_171, vtarget_info_offset_175, target_2, target_3, target_5, target_6)
and func_1(vsize_171, vtarget_info_len_174, vtarget_info_offset_175, target_2, target_1)
and func_2(target_2)
and func_3(vsize_171, target_3)
and func_5(vtarget_info_offset_175, target_5)
and func_6(vtarget_info_offset_175, target_6)
and vsize_171.getType().hasName("size_t")
and vtarget_info_len_174.getType().hasName("unsigned short")
and vtarget_info_offset_175.getType().hasName("unsigned int")
and vsize_171.getParentScope+() = func
and vtarget_info_len_174.getParentScope+() = func
and vtarget_info_offset_175.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
