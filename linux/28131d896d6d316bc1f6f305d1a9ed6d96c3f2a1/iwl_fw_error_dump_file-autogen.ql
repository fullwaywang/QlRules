/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_error_dump_file
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fw-error-dump-file
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_error_dump_file CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_759, Variable vdump_data_764, Variable vaddr_968, Variable vdata_size_969) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_mem"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vaddr_968
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_data_764
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_size_969
		and target_0.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget()=vdata_size_969
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("iwl_fw_dbg_is_d3_debug_enabled")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfwrt_759
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="d3_debug_data"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dump"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759)
}

predicate func_1(Parameter vfwrt_759) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="trans"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfwrt_759)
}

predicate func_2(Variable vdump_data_764) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdump_data_764)
}

predicate func_3(Parameter vfwrt_759, Variable vdump_data_764, Variable vaddr_968, Variable vdata_size_969) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("iwl_trans_read_mem")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="trans"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_3.getArgument(1).(VariableAccess).getTarget()=vaddr_968
		and target_3.getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_data_764
		and target_3.getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_size_969
		and target_3.getArgument(3).(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vdata_size_969
		and target_3.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getArgument(3).(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4")
}

predicate func_4(Parameter vfwrt_759, Variable vdump_data_764, Variable vaddr_968, Variable vdata_size_969) {
	exists(DivExpr target_4 |
		target_4.getLeftOperand().(VariableAccess).getTarget()=vdata_size_969
		and target_4.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_trans_read_mem")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="trans"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_759
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vaddr_968
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_data_764
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_size_969)
}

from Function func, Parameter vfwrt_759, Variable vdump_data_764, Variable vaddr_968, Variable vdata_size_969
where
not func_0(vfwrt_759, vdump_data_764, vaddr_968, vdata_size_969)
and vfwrt_759.getType().hasName("iwl_fw_runtime *")
and func_1(vfwrt_759)
and vdump_data_764.getType().hasName("iwl_fw_error_dump_data *")
and func_2(vdump_data_764)
and vaddr_968.getType().hasName("u32")
and func_3(vfwrt_759, vdump_data_764, vaddr_968, vdata_size_969)
and vdata_size_969.getType().hasName("size_t")
and func_4(vfwrt_759, vdump_data_764, vaddr_968, vdata_size_969)
and vfwrt_759.getParentScope+() = func
and vdump_data_764.getParentScope+() = func
and vaddr_968.getParentScope+() = func
and vdata_size_969.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
