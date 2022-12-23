/**
 * @name linux-c4eb1f403243fc7bbb7de644db8587c03de36da6-__htab_map_lookup_and_delete_batch
 * @id cpp/linux/c4eb1f403243fc7bbb7de644db8587c03de36da6/__htab_map_lookup_and_delete_batch
 * @description linux-c4eb1f403243fc7bbb7de644db8587c03de36da6-__htab_map_lookup_and_delete_batch 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_size_1513, Variable vbucket_size_1518) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kvmalloc")
		and not target_0.getTarget().hasName("kvmalloc_array")
		and target_0.getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vkey_size_1513
		and target_0.getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbucket_size_1518
		and target_0.getArgument(1).(BitwiseOrExpr).getValue()="1060032"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="1051840"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3264"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_0.getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8192")
}

predicate func_1(Variable vvalue_size_1513, Variable vbucket_size_1518) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("kvmalloc")
		and not target_1.getTarget().hasName("kvmalloc_array")
		and target_1.getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vvalue_size_1513
		and target_1.getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbucket_size_1518
		and target_1.getArgument(1).(BitwiseOrExpr).getValue()="1060032"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="1051840"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3264"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="1048576"
		and target_1.getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="8192")
}

from Function func, Variable vkey_size_1513, Variable vvalue_size_1513, Variable vbucket_size_1518
where
func_0(vkey_size_1513, vbucket_size_1518)
and func_1(vvalue_size_1513, vbucket_size_1518)
and vkey_size_1513.getType().hasName("u32")
and vvalue_size_1513.getType().hasName("u32")
and vbucket_size_1518.getType().hasName("u32")
and vkey_size_1513.getParentScope+() = func
and vvalue_size_1513.getParentScope+() = func
and vbucket_size_1518.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
