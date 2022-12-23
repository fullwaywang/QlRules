/**
 * @name linux-66e3531b33ee51dad17c463b4d9c9f52e341503d-setup_netfront
 * @id cpp/linux/66e3531b33ee51dad17c463b4d9c9f52e341503d/setup_netfront
 * @description linux-66e3531b33ee51dad17c463b4d9c9f52e341503d-setup_netfront CVE-2022-23042
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Parameter vqueue_1916, Variable vrxs_1919, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_1.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gnttab_end_foreign_access")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rx_ring_ref"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1916
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrxs_1919
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rx_ring_ref"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1916
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getStmt(27)=target_1)
}

predicate func_4(Parameter vqueue_1916, Variable vtxs_1918, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gnttab_end_foreign_access")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tx_ring_ref"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1916
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtxs_1918
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tx_ring_ref"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1916
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getStmt(28)=target_4)
}

predicate func_7(Parameter vqueue_1916) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="rx_ring_ref"
		and target_7.getQualifier().(VariableAccess).getTarget()=vqueue_1916)
}

predicate func_8(Variable vrxs_1919, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("free_pages")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrxs_1919
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Parameter vqueue_1916) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="tx_ring_ref"
		and target_9.getQualifier().(VariableAccess).getTarget()=vqueue_1916)
}

predicate func_10(Variable vtxs_1918, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("free_pages")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtxs_1918
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="0"
		and target_11.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("gnttab_end_foreign_access_ref")
		and target_13.getArgument(0) instanceof PointerFieldAccess
		and target_13.getArgument(1) instanceof Literal
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(LabelStmt target_14 |
		target_14.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_16(Function func) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("gnttab_end_foreign_access_ref")
		and target_16.getArgument(0) instanceof PointerFieldAccess
		and target_16.getArgument(1) instanceof Literal
		and target_16.getEnclosingFunction() = func)
}

predicate func_19(Parameter vqueue_1916) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("setup_netfront_single")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vqueue_1916)
}

predicate func_21(Variable vtxs_1918, Variable vgref_1920, Parameter vdev_1915) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("xenbus_grant_ring")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vdev_1915
		and target_21.getArgument(1).(VariableAccess).getTarget()=vtxs_1918
		and target_21.getArgument(2).(Literal).getValue()="1"
		and target_21.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgref_1920)
}

predicate func_22(Variable vrxs_1919, Variable vgref_1920, Parameter vdev_1915) {
	exists(FunctionCall target_22 |
		target_22.getTarget().hasName("xenbus_grant_ring")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vdev_1915
		and target_22.getArgument(1).(VariableAccess).getTarget()=vrxs_1919
		and target_22.getArgument(2).(Literal).getValue()="1"
		and target_22.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgref_1920)
}

from Function func, Parameter vqueue_1916, Variable vtxs_1918, Variable vrxs_1919, Variable vgref_1920, Parameter vdev_1915
where
not func_0(func)
and not func_1(vqueue_1916, vrxs_1919, func)
and not func_4(vqueue_1916, vtxs_1918, func)
and func_7(vqueue_1916)
and func_8(vrxs_1919, func)
and func_9(vqueue_1916)
and func_10(vtxs_1918, func)
and func_11(func)
and func_13(func)
and func_14(func)
and func_16(func)
and vqueue_1916.getType().hasName("netfront_queue *")
and func_19(vqueue_1916)
and vtxs_1918.getType().hasName("xen_netif_tx_sring *")
and func_21(vtxs_1918, vgref_1920, vdev_1915)
and vrxs_1919.getType().hasName("xen_netif_rx_sring *")
and func_22(vrxs_1919, vgref_1920, vdev_1915)
and vgref_1920.getType().hasName("grant_ref_t")
and vdev_1915.getType().hasName("xenbus_device *")
and vqueue_1916.getParentScope+() = func
and vtxs_1918.getParentScope+() = func
and vrxs_1919.getParentScope+() = func
and vgref_1920.getParentScope+() = func
and vdev_1915.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
