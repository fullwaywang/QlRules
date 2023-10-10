/**
 * @name libarchive-8312eaa576014cd9b965012af51bc1f967b12423-parse_rockridge
 * @id cpp/libarchive/8312eaa576014cd9b965012af51bc1f967b12423/parse-rockridge
 * @description libarchive-8312eaa576014cd9b965012af51bc1f967b12423-libarchive/archive_read_support_format_iso9660.c-parse_rockridge CVE-2019-1000020
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter va_2101, EqualityOperation target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("int")
		and target_1.getThen() instanceof ReturnStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2101
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="84"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Tried to parse Rockridge extensions, but none found"
		and target_1.getElse().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-20"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter va_2101, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("register_CE")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_2101
		and target_3.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter va_2101, ReturnStmt target_2, EqualityOperation target_3
where
not func_0(func)
and not func_1(va_2101, target_3, func)
and func_2(func, target_2)
and func_3(va_2101, target_3)
and va_2101.getType().hasName("archive_read *")
and va_2101.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
