/**
 * @name linux-6e8ab72a812396996035a37e5ca4b3b99b5d214b-ext4_destroy_inline_data_nolock
 * @id cpp/linux/6e8ab72a812396996035a37e5ca4b3b99b5d214b/ext4_destroy_inline_data_nolock
 * @description linux-6e8ab72a812396996035a37e5ca4b3b99b5d214b-ext4_destroy_inline_data_nolock CVE-2018-10881
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vei_406, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="i_data"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vei_406
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getValue()="60"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="4"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(AddExpr).getValue()="15"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Variable vei_406) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_inline_off"
		and target_1.getQualifier().(VariableAccess).getTarget()=vei_406)
}

from Function func, Variable vei_406
where
not func_0(vei_406, func)
and vei_406.getType().hasName("ext4_inode_info *")
and func_1(vei_406)
and vei_406.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
