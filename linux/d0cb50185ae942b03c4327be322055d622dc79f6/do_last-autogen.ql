/**
 * @name linux-d0cb50185ae942b03c4327be322055d622dc79f6-do_last
 * @id cpp/linux/d0cb50185ae942b03c4327be322055d622dc79f6/do_last
 * @description linux-d0cb50185ae942b03c4327be322055d622dc79f6-do_last 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdir_3203, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="i_uid"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_3203
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_0)
}

predicate func_1(Variable vdir_3203, Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d_inode"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_3203
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_1)
}

from Function func, Variable vdir_3203
where
not func_0(vdir_3203, func)
and not func_1(vdir_3203, func)
and vdir_3203.getType().hasName("dentry *")
and vdir_3203.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
