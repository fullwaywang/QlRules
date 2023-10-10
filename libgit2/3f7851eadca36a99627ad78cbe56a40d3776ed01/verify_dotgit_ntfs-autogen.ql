/**
 * @name libgit2-3f7851eadca36a99627ad78cbe56a40d3776ed01-verify_dotgit_ntfs
 * @id cpp/libgit2/3f7851eadca36a99627ad78cbe56a40d3776ed01/verify-dotgit-ntfs
 * @description libgit2-3f7851eadca36a99627ad78cbe56a40d3776ed01-src/path.c-verify_dotgit_ntfs CVE-2020-12278
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpath_1605, Variable vstart_1609, ReturnStmt target_2, LogicalAndExpr target_3, EqualityOperation target_1, NotExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpath_1605
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstart_1609
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpath_1605, Variable vstart_1609, ReturnStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpath_1605
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstart_1609
		and target_1.getAnOperand().(CharLiteral).getValue()="92"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
}

predicate func_3(Parameter vpath_1605, LogicalAndExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strncasecmp")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1605
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vstart_1609, NotExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vstart_1609
}

from Function func, Parameter vpath_1605, Variable vstart_1609, EqualityOperation target_1, ReturnStmt target_2, LogicalAndExpr target_3, NotExpr target_4
where
not func_0(vpath_1605, vstart_1609, target_2, target_3, target_1, target_4)
and func_1(vpath_1605, vstart_1609, target_2, target_1)
and func_2(target_2)
and func_3(vpath_1605, target_3)
and func_4(vstart_1609, target_4)
and vpath_1605.getType().hasName("const char *")
and vstart_1609.getType().hasName("size_t")
and vpath_1605.getParentScope+() = func
and vstart_1609.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
