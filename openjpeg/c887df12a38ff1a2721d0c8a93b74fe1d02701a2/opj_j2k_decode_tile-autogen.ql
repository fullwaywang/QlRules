/**
 * @name openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-opj_j2k_decode_tile
 * @id cpp/openjpeg/c887df12a38ff1a2721d0c8a93b74fe1d02701a2/opj-j2k-decode-tile
 * @description openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-src/lib/openjp2/j2k.c-opj_j2k_decode_tile CVE-2015-1239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_tcp_8170, NotExpr target_3, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("opj_j2k_tcp_destroy")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_8170
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_1(NotExpr target_3, Function func, ReturnStmt target_1) {
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vp_manager_8166, Variable vl_tcp_8170, Function func, IfStmt target_2) {
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("opj_j2k_merge_ppt")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_tcp_8170
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_manager_8166
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(NotExpr target_3) {
		target_3.getOperand() instanceof FunctionCall
}

from Function func, Parameter vp_manager_8166, Variable vl_tcp_8170, ExprStmt target_0, ReturnStmt target_1, IfStmt target_2, NotExpr target_3
where
func_0(vl_tcp_8170, target_3, target_0)
and func_1(target_3, func, target_1)
and func_2(vp_manager_8166, vl_tcp_8170, func, target_2)
and func_3(target_3)
and vp_manager_8166.getType().hasName("opj_event_mgr_t *")
and vl_tcp_8170.getType().hasName("opj_tcp_t *")
and vp_manager_8166.getParentScope+() = func
and vl_tcp_8170.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
