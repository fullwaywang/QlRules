/**
 * @name libplist-26061aac4ec75e7a4469a9aab9a424716223e5c4-plist_from_bin
 * @id cpp/libplist/26061aac4ec75e7a4469a9aab9a424716223e5c4/plist-from-bin
 * @description libplist-26061aac4ec75e7a4469a9aab9a424716223e5c4-src/bplist.c-plist_from_bin CVE-2017-5835
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable voffset_size_706, ExprStmt target_1, RelationalOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voffset_size_706
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable voffset_size_706, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_size_706
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_2(Variable voffset_size_706, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=voffset_size_706
}

from Function func, Variable voffset_size_706, ExprStmt target_1, RelationalOperation target_2
where
not func_0(voffset_size_706, target_1, target_2, func)
and func_1(voffset_size_706, target_1)
and func_2(voffset_size_706, target_2)
and voffset_size_706.getType().hasName("uint8_t")
and voffset_size_706.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
