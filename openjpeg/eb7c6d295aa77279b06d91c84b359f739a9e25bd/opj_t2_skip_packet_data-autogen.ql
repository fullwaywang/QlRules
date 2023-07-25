/**
 * @name openjpeg-eb7c6d295aa77279b06d91c84b359f739a9e25bd-opj_t2_skip_packet_data
 * @id cpp/openjpeg/eb7c6d295aa77279b06d91c84b359f739a9e25bd/opj-t2-skip-packet-data
 * @description openjpeg-eb7c6d295aa77279b06d91c84b359f739a9e25bd-src/lib/openjp2/t2.c-opj_t2_skip_packet_data CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_data_read_1217, Variable vl_seg_1245, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1, ExprStmt target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_data_read_1217
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="newlen"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_seg_1245
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_data_read_1217
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_data_read_1217, Parameter vp_max_length_1218, Variable vl_seg_1245, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_data_read_1217
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="newlen"
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_seg_1245
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vp_max_length_1218
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vp_max_length_1218, Variable vl_seg_1245, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fprintf")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="skip: segment too long (%d) with max (%d) for codeblock %d (p=%d, b=%d, r=%d, c=%d)\n"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="newlen"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_seg_1245
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_max_length_1218
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="precno"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="resno"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="compno"
}

predicate func_3(Parameter vp_data_read_1217, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_data_read_1217
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vl_seg_1245, ExprStmt target_4) {
		target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_seg_1245
}

from Function func, Parameter vp_data_read_1217, Parameter vp_max_length_1218, Variable vl_seg_1245, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vp_data_read_1217, vl_seg_1245, target_2, target_3, target_1, target_4)
and func_1(vp_data_read_1217, vp_max_length_1218, vl_seg_1245, target_2, target_1)
and func_2(vp_max_length_1218, vl_seg_1245, target_2)
and func_3(vp_data_read_1217, target_3)
and func_4(vl_seg_1245, target_4)
and vp_data_read_1217.getType().hasName("OPJ_UINT32 *")
and vp_max_length_1218.getType().hasName("OPJ_UINT32")
and vl_seg_1245.getType().hasName("opj_tcd_seg_t *")
and vp_data_read_1217.getParentScope+() = func
and vp_max_length_1218.getParentScope+() = func
and vl_seg_1245.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
