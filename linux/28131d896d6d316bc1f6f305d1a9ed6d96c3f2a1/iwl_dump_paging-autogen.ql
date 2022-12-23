/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_paging
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dump-paging
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dump_paging CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_729, Variable vi_732, Variable vpaging_736) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_729
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_729
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_729
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_729
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="fw_offs"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="fw_paging_db"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_729
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_732
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpaging_736
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(MulExpr).getValue()="32768"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12")
}

predicate func_1(Parameter vfwrt_729) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="trans"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfwrt_729)
}

predicate func_2(Variable vi_732, Variable vpaging_736) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpaging_736
		and target_2.getRValue().(VariableAccess).getTarget()=vi_732)
}

predicate func_3(Variable vpaging_736) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="data"
		and target_3.getQualifier().(VariableAccess).getTarget()=vpaging_736)
}

from Function func, Parameter vfwrt_729, Variable vi_732, Variable vpaging_736
where
not func_0(vfwrt_729, vi_732, vpaging_736)
and vfwrt_729.getType().hasName("iwl_fw_runtime *")
and func_1(vfwrt_729)
and vi_732.getType().hasName("int")
and func_2(vi_732, vpaging_736)
and vpaging_736.getType().hasName("iwl_fw_error_dump_paging *")
and func_3(vpaging_736)
and vfwrt_729.getParentScope+() = func
and vi_732.getParentScope+() = func
and vpaging_736.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
