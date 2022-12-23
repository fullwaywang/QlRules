/**
 * @name linux-d0cb50185ae942b03c4327be322055d622dc79f6-may_create_in_sticky
 * @id cpp/linux/d0cb50185ae942b03c4327be322055d622dc79f6/may_create_in_sticky
 * @description linux-d0cb50185ae942b03c4327be322055d622dc79f6-may_create_in_sticky 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_4(Parameter vdir_1020) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="i_mode"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_1020)
}

predicate func_5(Parameter vdir_1020) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="i_uid"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_1020)
}

from Function func, Parameter vdir_1020
where
func_4(vdir_1020)
and func_5(vdir_1020)
and vdir_1020.getType().hasName("dentry *const")
and vdir_1020.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
