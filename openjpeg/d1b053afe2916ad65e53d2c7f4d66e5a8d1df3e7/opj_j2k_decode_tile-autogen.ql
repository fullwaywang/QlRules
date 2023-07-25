/**
 * @name openjpeg-d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7-opj_j2k_decode_tile
 * @id cpp/openjpeg/d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7/opj-j2k-decode-tile
 * @description openjpeg-d1b053afe2916ad65e53d2c7f4d66e5a8d1df3e7-src/lib/openjp2/j2k.c-opj_j2k_decode_tile CVE-2015-1239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_8093, Variable vl_tcp_8097, ExprStmt target_1, ExprStmt target_2, NotExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("opj_j2k_merge_ppt")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_8097
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_manager_8093
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_j2k_tcp_destroy")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_8097
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_8093, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_8093
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to decode.\n"
}

predicate func_2(Variable vl_tcp_8097, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("opj_j2k_tcp_destroy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_8097
}

predicate func_3(Variable vl_tcp_8097, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("opj_tcd_decode_tile")
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="m_tcd"
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="m_data"
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_8097
		and target_3.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="m_data_size"
		and target_3.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tcp_8097
		and target_3.getOperand().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="cstr_index"
}

from Function func, Parameter vp_manager_8093, Variable vl_tcp_8097, ExprStmt target_1, ExprStmt target_2, NotExpr target_3
where
not func_0(vp_manager_8093, vl_tcp_8097, target_1, target_2, target_3, func)
and func_1(vp_manager_8093, target_1)
and func_2(vl_tcp_8097, target_2)
and func_3(vl_tcp_8097, target_3)
and vp_manager_8093.getType().hasName("opj_event_mgr_t *")
and vl_tcp_8097.getType().hasName("opj_tcp_t *")
and vp_manager_8093.getParentScope+() = func
and vl_tcp_8097.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
