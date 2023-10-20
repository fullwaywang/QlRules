/**
 * @name openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-opj_j2k_read_header_procedure
 * @id cpp/openjpeg/c887df12a38ff1a2721d0c8a93b74fe1d02701a2/opj-j2k-read-header-procedure
 * @description openjpeg-c887df12a38ff1a2721d0c8a93b74fe1d02701a2-src/lib/openjp2/j2k.c-opj_j2k_read_header_procedure CVE-2015-1239
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_7248, Parameter vp_j2k_7246, ExprStmt target_1, ExprStmt target_2, ValueFieldAccess target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("opj_j2k_merge_ppm")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="m_cp"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7246
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_manager_7248
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7248
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to merge PPM data\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_7248, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7248
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="required QCD marker not found in main header\n"
}

predicate func_2(Parameter vp_manager_7248, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_7248
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Main header has been correctly decoded.\n"
}

predicate func_3(Parameter vp_j2k_7246, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="m_decoder"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="m_specific_param"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7246
}

predicate func_4(Parameter vp_j2k_7246, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="main_head_end"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cstr_index"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_j2k_7246
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("opj_stream_tell")
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vp_manager_7248, Parameter vp_j2k_7246, ExprStmt target_1, ExprStmt target_2, ValueFieldAccess target_3, ExprStmt target_4
where
not func_0(vp_manager_7248, vp_j2k_7246, target_1, target_2, target_3, target_4, func)
and func_1(vp_manager_7248, target_1)
and func_2(vp_manager_7248, target_2)
and func_3(vp_j2k_7246, target_3)
and func_4(vp_j2k_7246, target_4)
and vp_manager_7248.getType().hasName("opj_event_mgr_t *")
and vp_j2k_7246.getType().hasName("opj_j2k_t *")
and vp_manager_7248.getParentScope+() = func
and vp_j2k_7246.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
