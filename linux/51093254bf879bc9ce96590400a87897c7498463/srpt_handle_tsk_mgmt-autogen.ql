/**
 * @name linux-51093254bf879bc9ce96590400a87897c7498463-srpt_handle_tsk_mgmt
 * @id cpp/linux/51093254bf879bc9ce96590400a87897c7498463/srpt_handle_tsk_mgmt
 * @description linux-51093254bf879bc9ce96590400a87897c7498463-srpt_handle_tsk_mgmt 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsend_ioctx_1742) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="response"
		and target_0.getQualifier().(ValueFieldAccess).getTarget().getName()="se_tmr_req"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_0.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsend_ioctx_1742
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue() instanceof EnumConstantAccess)
}

predicate func_1(Variable vsrp_tsk_1744) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="task_tag"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsrp_tsk_1744
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall)
}

predicate func_2(Parameter vsend_ioctx_1742) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="cmd"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsend_ioctx_1742)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vtcm_tmr_1749, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtcm_tmr_1749
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_4.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_7(Variable vsrp_tsk_1744, Variable vtag_1748, Variable vrc_1750, Parameter vsend_ioctx_1742, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tsk_mgmt_func"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_tsk_1744
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_1750
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("srpt_rx_mgmt_fn_tag")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsend_ioctx_1742
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_1750
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="response"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="se_tmr_req"
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_7.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtag_1748
		and target_7.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="task_tag"
		and target_7.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrp_tsk_1744
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_13(Variable vsrp_tsk_1744, Variable vsess_1746, Variable vunpacked_lun_1747, Variable vtag_1748, Variable vtcm_tmr_1749, Variable vrc_1750, Parameter vsend_ioctx_1742, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_1750
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("target_submit_tmr")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsend_ioctx_1742
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsess_1746
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vunpacked_lun_1747
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsrp_tsk_1744
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtcm_tmr_1749
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(BitwiseOrExpr).getValue()="37748928"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="4194304"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="33554432"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vtag_1748
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

from Function func, Variable vsrp_tsk_1744, Variable vsess_1746, Variable vunpacked_lun_1747, Variable vtag_1748, Variable vtcm_tmr_1749, Variable vrc_1750, Parameter vsend_ioctx_1742
where
func_0(vsend_ioctx_1742)
and func_1(vsrp_tsk_1744)
and func_2(vsend_ioctx_1742)
and func_3(func)
and func_4(vtcm_tmr_1749, func)
and func_7(vsrp_tsk_1744, vtag_1748, vrc_1750, vsend_ioctx_1742, func)
and func_13(vsrp_tsk_1744, vsess_1746, vunpacked_lun_1747, vtag_1748, vtcm_tmr_1749, vrc_1750, vsend_ioctx_1742, func)
and vsrp_tsk_1744.getType().hasName("srp_tsk_mgmt *")
and vsess_1746.getType().hasName("se_session *")
and vunpacked_lun_1747.getType().hasName("uint64_t")
and vtag_1748.getType().hasName("uint32_t")
and vtcm_tmr_1749.getType().hasName("int")
and vrc_1750.getType().hasName("int")
and vsend_ioctx_1742.getType().hasName("srpt_send_ioctx *")
and vsrp_tsk_1744.getParentScope+() = func
and vsess_1746.getParentScope+() = func
and vunpacked_lun_1747.getParentScope+() = func
and vtag_1748.getParentScope+() = func
and vtcm_tmr_1749.getParentScope+() = func
and vrc_1750.getParentScope+() = func
and vsend_ioctx_1742.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
