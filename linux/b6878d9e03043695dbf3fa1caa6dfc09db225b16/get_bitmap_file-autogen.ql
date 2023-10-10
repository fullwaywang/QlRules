/**
 * @name linux-b6878d9e03043695dbf3fa1caa6dfc09db225b16-get_bitmap_file
 * @id cpp/linux/b6878d9e03043695dbf3fa1caa6dfc09db225b16/get-bitmap-file
 * @description linux-b6878d9e03043695dbf3fa1caa6dfc09db225b16-get_bitmap_file 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_5758) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kmalloc")
		and not target_0.getTarget().hasName("kzalloc")
		and target_0.getArgument(0).(SizeofExprOperator).getValue()="4096"
		and target_0.getArgument(0).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfile_5758
		and target_0.getArgument(1).(Literal).getValue()="16")
}

from Function func, Variable vfile_5758
where
func_0(vfile_5758)
and vfile_5758.getType().hasName("mdu_bitmap_file_t *")
and vfile_5758.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
