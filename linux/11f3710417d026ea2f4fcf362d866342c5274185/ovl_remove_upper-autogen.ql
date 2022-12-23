/**
 * @name linux-11f3710417d026ea2f4fcf362d866342c5274185-ovl_remove_upper
 * @id cpp/linux/11f3710417d026ea2f4fcf362d866342c5274185/ovl_remove_upper
 * @description linux-11f3710417d026ea2f4fcf362d866342c5274185-ovl_remove_upper 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vupper_599) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dget")
		and not target_0.getTarget().hasName("lookup_one_len")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vupper_599)
}

predicate func_1(Parameter vdentry_595, Variable vupperdir_597, Variable vupper_599, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vupper_599
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_one_len")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdentry_595
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vupperdir_597
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="len"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_name"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdentry_595
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_4(Variable vupper_599, Variable verr_600) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=verr_600
		and target_4.getRValue().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupper_599)
}

predicate func_6(Variable vupper_599) {
	exists(GotoStmt target_6 |
		target_6.toString() = "goto ..."
		and target_6.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_6.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupper_599)
}

predicate func_7(Parameter vdentry_595, Parameter vis_dir_595, Variable vdir_598, Variable vupper_599, Variable verr_600, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vupper_599
		and target_7.getCondition().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vis_dir_595
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_600
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vfs_rmdir")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_598
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vupper_599
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_600
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vfs_unlink")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_598
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vupper_599
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ovl_dentry_version_inc")
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="d_parent"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdentry_595
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_7))
}

predicate func_9(Function func) {
	exists(LabelStmt target_9 |
		target_9.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_9))
}

predicate func_10(Parameter vdentry_595) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("ovl_dentry_upper")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vdentry_595)
}

predicate func_11(Variable vupperdir_597, Variable vupper_599) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("dput")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vupper_599
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof PointerFieldAccess
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vupperdir_597)
}

predicate func_15(Function func) {
	exists(Initializer target_15 |
		target_15.getExpr() instanceof FunctionCall
		and target_15.getExpr().getEnclosingFunction() = func)
}

predicate func_16(Variable vupper_599) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="d_parent"
		and target_16.getQualifier().(VariableAccess).getTarget()=vupper_599)
}

from Function func, Parameter vdentry_595, Parameter vis_dir_595, Variable vupperdir_597, Variable vdir_598, Variable vupper_599, Variable verr_600
where
func_0(vupper_599)
and not func_1(vdentry_595, vupperdir_597, vupper_599, func)
and not func_4(vupper_599, verr_600)
and not func_6(vupper_599)
and not func_7(vdentry_595, vis_dir_595, vdir_598, vupper_599, verr_600, func)
and not func_9(func)
and func_10(vdentry_595)
and func_11(vupperdir_597, vupper_599)
and func_15(func)
and func_16(vupper_599)
and vdentry_595.getType().hasName("dentry *")
and vis_dir_595.getType().hasName("bool")
and vupperdir_597.getType().hasName("dentry *")
and vdir_598.getType().hasName("inode *")
and vupper_599.getType().hasName("dentry *")
and verr_600.getType().hasName("int")
and vdentry_595.getParentScope+() = func
and vis_dir_595.getParentScope+() = func
and vupperdir_597.getParentScope+() = func
and vdir_598.getParentScope+() = func
and vupper_599.getParentScope+() = func
and verr_600.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
