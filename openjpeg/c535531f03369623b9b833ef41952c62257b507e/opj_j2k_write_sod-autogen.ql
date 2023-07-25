/**
 * @name openjpeg-c535531f03369623b9b833ef41952c62257b507e-opj_j2k_write_sod
 * @id cpp/openjpeg/c535531f03369623b9b833ef41952c62257b507e/opj-j2k-write-sod
 * @description openjpeg-c535531f03369623b9b833ef41952c62257b507e-src/lib/openjp2/j2k.c-opj_j2k_write_sod CVE-2017-14039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_total_data_size_4605, Parameter vp_manager_4607, ExprStmt target_1, NotExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp_total_data_size_4605
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_4607
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough bytes in output buffer to write SOD marker\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_total_data_size_4605, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vp_total_data_size_4605
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_2(Parameter vp_manager_4607, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("opj_tcd_encode_tile")
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="m_current_tile_number"
		and target_2.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vp_manager_4607
}

from Function func, Parameter vp_total_data_size_4605, Parameter vp_manager_4607, ExprStmt target_1, NotExpr target_2
where
not func_0(vp_total_data_size_4605, vp_manager_4607, target_1, target_2, func)
and func_1(vp_total_data_size_4605, target_1)
and func_2(vp_manager_4607, target_2)
and vp_total_data_size_4605.getType().hasName("OPJ_UINT32")
and vp_manager_4607.getType().hasName("opj_event_mgr_t *")
and vp_total_data_size_4605.getParentScope+() = func
and vp_manager_4607.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
