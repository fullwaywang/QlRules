/**
 * @name linux-a659daf63d16aa883be42f3f34ff84235c302198-mon_bin_mmap
 * @id cpp/linux/a659daf63d16aa883be42f3f34ff84235c302198/mon-bin-mmap
 * @description linux-a659daf63d16aa883be42f3f34ff84235c302198-mon_bin_mmap 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvma_1267, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_1267
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vvma_1267, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_1267
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="18446744073709551583"
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(Literal).getValue()="32"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vvma_1267) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="vm_ops"
		and target_2.getQualifier().(VariableAccess).getTarget()=vvma_1267)
}

from Function func, Parameter vvma_1267
where
not func_0(vvma_1267, func)
and not func_1(vvma_1267, func)
and vvma_1267.getType().hasName("vm_area_struct *")
and func_2(vvma_1267)
and vvma_1267.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
