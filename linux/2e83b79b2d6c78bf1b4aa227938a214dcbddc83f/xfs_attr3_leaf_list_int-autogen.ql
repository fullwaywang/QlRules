/**
 * @name linux-2e83b79b2d6c78bf1b4aa227938a214dcbddc83f-xfs_attr3_leaf_list_int
 * @id cpp/linux/2e83b79b2d6c78bf1b4aa227938a214dcbddc83f/xfs_attr3_leaf_list_int
 * @description linux-2e83b79b2d6c78bf1b4aa227938a214dcbddc83f-xfs_attr3_leaf_list_int 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vretval_371) {
	exists(NotExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vretval_371
		and target_0.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_1(Parameter vcontext_364, Variable vretval_371) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vretval_371
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vretval_371
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="put_value"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_364)
}

predicate func_2(Parameter vcontext_364, Variable ventry_370, Variable vretval_371, Variable vname_rmt_438, Variable vvaluelen_441, Variable vargs_444) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_371
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="put_listent"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_364
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vcontext_364
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_370
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vname_rmt_438
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="namelen"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vname_rmt_438
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(4).(VariableAccess).getTarget()=vvaluelen_441
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="value"
		and target_2.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(5).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vargs_444
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="put_value"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontext_364)
}

predicate func_3(Variable vretval_371) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(VariableAccess).getTarget()=vretval_371
		and target_3.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vretval_371)
}

from Function func, Parameter vcontext_364, Variable ventry_370, Variable vretval_371, Variable vname_rmt_438, Variable vvaluelen_441, Variable vargs_444
where
not func_0(vretval_371)
and func_1(vcontext_364, vretval_371)
and func_2(vcontext_364, ventry_370, vretval_371, vname_rmt_438, vvaluelen_441, vargs_444)
and func_3(vretval_371)
and vcontext_364.getType().hasName("xfs_attr_list_context *")
and ventry_370.getType().hasName("xfs_attr_leaf_entry *")
and vretval_371.getType().hasName("int")
and vname_rmt_438.getType().hasName("xfs_attr_leaf_name_remote_t *")
and vvaluelen_441.getType().hasName("int")
and vargs_444.getType().hasName("xfs_da_args_t")
and vcontext_364.getParentScope+() = func
and ventry_370.getParentScope+() = func
and vretval_371.getParentScope+() = func
and vname_rmt_438.getParentScope+() = func
and vvaluelen_441.getParentScope+() = func
and vargs_444.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
