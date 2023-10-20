/**
 * @name openjpeg-efb70af001401c2cf3e9e60e308225ceb95ae9b6-opj_j2k_setup_encoder
 * @id cpp/openjpeg/efb70af001401c2cf3e9e60e308225ceb95ae9b6/opj-j2k-setup-encoder
 * @description openjpeg-efb70af001401c2cf3e9e60e308225ceb95ae9b6-src/lib/openjp2/j2k.c-opj_j2k_setup_encoder CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_6144, Parameter vparameters_6142, ExprStmt target_1, LogicalOrExpr target_2, EqualityOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="numresolution"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparameters_6142
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="numresolution"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparameters_6142
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="33"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_6144
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid number of resolutions : %d not in range [1,%d]\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="numresolution"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparameters_6142
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="33"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_6144, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_6144
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Deprecated fields cp_cinema or cp_rsiz are used\nPlease consider using only the rsiz field\nSee openjpeg.h documentation for more details\n"
}

predicate func_2(Parameter vparameters_6142, LogicalOrExpr target_2) {
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vparameters_6142
}

predicate func_3(Parameter vparameters_6142, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="rsiz"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparameters_6142
		and target_3.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vp_manager_6144, Parameter vparameters_6142, ExprStmt target_1, LogicalOrExpr target_2, EqualityOperation target_3
where
not func_0(vp_manager_6144, vparameters_6142, target_1, target_2, target_3, func)
and func_1(vp_manager_6144, target_1)
and func_2(vparameters_6142, target_2)
and func_3(vparameters_6142, target_3)
and vp_manager_6144.getType().hasName("opj_event_mgr_t *")
and vparameters_6142.getType().hasName("opj_cparameters_t *")
and vp_manager_6144.getParentScope+() = func
and vparameters_6142.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
