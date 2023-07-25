/**
 * @name imagemagick-33d1b9590c401d4aee666ffd10b16868a38cf705-formatIPTCfromBuffer
 * @id cpp/imagemagick/33d1b9590c401d4aee666ffd10b16868a38cf705/formatIPTCfromBuffer
 * @description imagemagick-33d1b9590c401d4aee666ffd10b16868a38cf705-coders/meta.c-formatIPTCfromBuffer CVE-2018-16750
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_4, Function func) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vstr_2016, RelationalOperation target_5, EqualityOperation target_4, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_2016
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstr_2016
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_4, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("printf")
		and target_2.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func
}

predicate func_3(RelationalOperation target_5, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(IfStmt).getCondition()=target_5
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vstr_2016, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vstr_2016
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vstr_2016, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstr_2016
}

from Function func, Variable vstr_2016, ExprStmt target_2, ReturnStmt target_3, EqualityOperation target_4, RelationalOperation target_5, ExprStmt target_6
where
not func_0(target_4, func)
and not func_1(vstr_2016, target_5, target_4, target_6)
and func_2(target_4, func, target_2)
and func_3(target_5, func, target_3)
and func_4(vstr_2016, target_4)
and func_5(target_5)
and func_6(vstr_2016, target_6)
and vstr_2016.getType().hasName("unsigned char *")
and vstr_2016.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
