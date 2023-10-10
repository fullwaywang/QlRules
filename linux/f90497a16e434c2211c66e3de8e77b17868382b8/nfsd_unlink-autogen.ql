/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_unlink
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-unlink
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_unlink 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtype_1718) {
	exists(DeclStmt target_0 |
		target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1718
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="16384")
}

predicate func_1(Parameter vtype_1718, Variable vrdentry_1721, Variable vdirp_1722, Variable vhost_err_1725, Variable vinit_user_ns) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhost_err_1725
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vfs_unlink")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vinit_user_ns
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdirp_1722
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrdentry_1721
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1718
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="16384")
}

from Function func, Parameter vtype_1718, Variable vrdentry_1721, Variable vdirp_1722, Variable vhost_err_1725, Variable vinit_user_ns
where
not func_0(vtype_1718)
and func_1(vtype_1718, vrdentry_1721, vdirp_1722, vhost_err_1725, vinit_user_ns)
and vtype_1718.getType().hasName("int")
and vrdentry_1721.getType().hasName("dentry *")
and vdirp_1722.getType().hasName("inode *")
and vhost_err_1725.getType().hasName("int")
and vinit_user_ns.getType().hasName("user_namespace")
and vtype_1718.getParentScope+() = func
and vrdentry_1721.getParentScope+() = func
and vdirp_1722.getParentScope+() = func
and vhost_err_1725.getParentScope+() = func
and not vinit_user_ns.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
