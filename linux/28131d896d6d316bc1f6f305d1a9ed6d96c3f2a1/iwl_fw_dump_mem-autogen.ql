/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_dump_mem
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fw-dump-mem
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_dump_mem CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_647, Parameter vofs_647, Variable vdump_mem_649, Parameter vfwrt_645, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vofs_647
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_mem_649
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vlen_647
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vlen_647, Parameter vofs_647, Variable vdump_mem_649, Parameter vfwrt_645) {
	exists(DivExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vlen_647
		and target_1.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_trans_read_mem")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="trans"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vofs_647
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_mem_649)
}

predicate func_2(Parameter vlen_647, Parameter vofs_647, Variable vdump_mem_649, Parameter vfwrt_645) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("iwl_trans_read_mem")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="trans"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_645
		and target_2.getArgument(1).(VariableAccess).getTarget()=vofs_647
		and target_2.getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_mem_649
		and target_2.getArgument(3).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_647
		and target_2.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4")
}

predicate func_3(Variable vdump_mem_649) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="data"
		and target_3.getQualifier().(VariableAccess).getTarget()=vdump_mem_649)
}

predicate func_4(Parameter vfwrt_645) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="trans"
		and target_4.getQualifier().(VariableAccess).getTarget()=vfwrt_645)
}

from Function func, Parameter vlen_647, Parameter vofs_647, Variable vdump_mem_649, Parameter vfwrt_645
where
not func_0(vlen_647, vofs_647, vdump_mem_649, vfwrt_645, func)
and vlen_647.getType().hasName("u32")
and func_1(vlen_647, vofs_647, vdump_mem_649, vfwrt_645)
and vofs_647.getType().hasName("u32")
and func_2(vlen_647, vofs_647, vdump_mem_649, vfwrt_645)
and vdump_mem_649.getType().hasName("iwl_fw_error_dump_mem *")
and func_3(vdump_mem_649)
and vfwrt_645.getType().hasName("iwl_fw_runtime *")
and func_4(vfwrt_645)
and vlen_647.getParentScope+() = func
and vofs_647.getParentScope+() = func
and vdump_mem_649.getParentScope+() = func
and vfwrt_645.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
