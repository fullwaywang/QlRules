/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_break_deleg_cb
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-break-deleg-cb
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_break_deleg_cb 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof EnumConstantAccess
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vret_4802) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vret_4802)
}

from Function func, Variable vret_4802
where
func_1(func)
and func_2(vret_4802)
and vret_4802.getType().hasName("bool")
and vret_4802.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
