/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_service_srng
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/ath11k-dp-service-srng
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath11k_dp_service_srng CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Parameter vab_737) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("const ath11k_hw_hal_params *")
		and target_1.getRValue().(ValueFieldAccess).getTarget().getName()="hal_params"
		and target_1.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_1.getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_737)
}

predicate func_2(Variable vgrp_id_742, Variable vid_808, Variable vrx_ring_822, Parameter vab_737) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("ath11k_dp_rxbufs_replenish")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vab_737
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vid_808
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrx_ring_822
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="rx_buf_rbm"
		and target_2.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("const ath11k_hw_hal_params *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="host2rxdma"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ring_mask"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw_params"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vab_737
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vgrp_id_742
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vid_808)
}

predicate func_5(Variable vid_808, Parameter vab_737) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("ath11k_ab_to_ar")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vab_737
		and target_5.getArgument(1).(VariableAccess).getTarget()=vid_808)
}

from Function func, Variable vgrp_id_742, Variable vid_808, Variable vrx_ring_822, Parameter vab_737
where
not func_0(func)
and not func_1(vab_737)
and not func_2(vgrp_id_742, vid_808, vrx_ring_822, vab_737)
and vgrp_id_742.getType().hasName("int")
and vid_808.getType().hasName("int")
and vrx_ring_822.getType().hasName("dp_rxdma_ring *")
and vab_737.getType().hasName("ath11k_base *")
and func_5(vid_808, vab_737)
and vgrp_id_742.getParentScope+() = func
and vid_808.getParentScope+() = func
and vrx_ring_822.getParentScope+() = func
and vab_737.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
