/**
 * @name openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-opj_j2k_read_tile_header
 * @id cpp/openjpeg/c887df12a38ff1a2721d0c8a93b74fe1d02701a2/opj-j2k-read-tile-header
 * @description openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-src/lib/openjp2/j2k.c-opj_j2k_read_tile_header CVE-2015-1239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_j2k_7898, Parameter vp_manager_7906, EqualityOperation target_1, NotExpr target_2, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("opj_j2k_merge_ppt")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="tcps"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_cp"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7898
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_current_tile_number"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7898
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_manager_7906
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7906
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to merge PPT data\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_j2k_7898, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="m_current_tile_number"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7898
}

predicate func_2(Parameter vp_j2k_7898, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("opj_tcd_init_decode_tile")
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="m_tcd"
		and target_2.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7898
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="m_current_tile_number"
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7898
}

predicate func_3(Parameter vp_manager_7906, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7906
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Stream too short\n"
}

predicate func_4(Parameter vp_manager_7906, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7906
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Cannot decode tile, memory error\n"
}

from Function func, Parameter vp_j2k_7898, Parameter vp_manager_7906, EqualityOperation target_1, NotExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vp_j2k_7898, vp_manager_7906, target_1, target_2, target_3, target_4, func)
and func_1(vp_j2k_7898, target_1)
and func_2(vp_j2k_7898, target_2)
and func_3(vp_manager_7906, target_3)
and func_4(vp_manager_7906, target_4)
and vp_j2k_7898.getType().hasName("opj_j2k_t *")
and vp_manager_7906.getType().hasName("opj_event_mgr_t *")
and vp_j2k_7898.getParentScope+() = func
and vp_manager_7906.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
