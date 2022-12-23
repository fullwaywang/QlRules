/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_txf
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fwrt-dump-txf
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_txf CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voffset_118, Parameter vfwrt_116, Variable vfifo_data_121, Variable vfifo_len_122, Variable vi_123) {
	exists(DivExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vfifo_len_122
		and target_0.getRightOperand() instanceof SizeofTypeOperator
		and target_0.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_123
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfifo_data_121
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_123
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_trans_read_prph")
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="trans"
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_116
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="10486856"
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_118)
}

predicate func_1(Parameter vfwrt_116, Variable vfifo_data_121, Variable vfifo_len_122, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_116
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_116
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="frob_txf"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sanitize_ops"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_116
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sanitize_ctx"
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_116
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vfifo_data_121
		and target_1.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vfifo_len_122
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_1))
}

predicate func_3(Function func) {
	exists(SizeofTypeOperator target_3 |
		target_3.getType() instanceof LongType
		and target_3.getValue()="4"
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Variable vfifo_len_122) {
	exists(AssignDivExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vfifo_len_122
		and target_5.getRValue() instanceof SizeofTypeOperator)
}

predicate func_6(Parameter vfwrt_116) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="trans"
		and target_6.getQualifier().(VariableAccess).getTarget()=vfwrt_116)
}

predicate func_7(Variable vfifo_hdr_120, Variable vfifo_data_121) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vfifo_data_121
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfifo_hdr_120)
}

predicate func_8(Parameter vdump_data_117, Variable vfifo_hdr_120, Variable vfifo_len_122) {
	exists(AddExpr target_8 |
		target_8.getAnOperand().(VariableAccess).getTarget()=vfifo_len_122
		and target_8.getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_8.getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfifo_hdr_120
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdump_data_117)
}

from Function func, Parameter vdump_data_117, Parameter voffset_118, Parameter vfwrt_116, Variable vfifo_hdr_120, Variable vfifo_data_121, Variable vfifo_len_122, Variable vi_123
where
not func_0(voffset_118, vfwrt_116, vfifo_data_121, vfifo_len_122, vi_123)
and not func_1(vfwrt_116, vfifo_data_121, vfifo_len_122, func)
and func_3(func)
and func_5(vfifo_len_122)
and voffset_118.getType().hasName("u32")
and vfwrt_116.getType().hasName("iwl_fw_runtime *")
and func_6(vfwrt_116)
and vfifo_data_121.getType().hasName("u32 *")
and func_7(vfifo_hdr_120, vfifo_data_121)
and vfifo_len_122.getType().hasName("u32")
and func_8(vdump_data_117, vfifo_hdr_120, vfifo_len_122)
and vi_123.getType().hasName("int")
and vdump_data_117.getParentScope+() = func
and voffset_118.getParentScope+() = func
and vfwrt_116.getParentScope+() = func
and vfifo_hdr_120.getParentScope+() = func
and vfifo_data_121.getParentScope+() = func
and vfifo_len_122.getParentScope+() = func
and vi_123.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
