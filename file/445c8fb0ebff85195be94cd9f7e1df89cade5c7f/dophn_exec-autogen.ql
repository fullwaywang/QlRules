/**
 * @name file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-dophn_exec
 * @id cpp/file/445c8fb0ebff85195be94cd9f7e1df89cade5c7f/dophn-exec
 * @description file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-src/readelf.c-dophn_exec CVE-2014-9653
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vclazz_1162, BlockStmt target_5, EqualityOperation target_6, ConditionalExpr target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof FunctionCall
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getGreaterOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_0.getGreaterOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vfd_1162, Parameter voff_1162, Variable vph32_1165, Variable vph64_1166, Parameter vclazz_1162, BlockStmt target_5, UnaryMinusExpr target_3) {
		target_3.getValue()="-1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_1162
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_1165
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_1166
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voff_1162
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
}

/*predicate func_4(Parameter vfd_1162, Parameter voff_1162, Variable vph32_1165, Variable vph64_1166, Parameter vclazz_1162, FunctionCall target_4) {
		target_4.getTarget().hasName("pread")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vfd_1162
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_1165
		and target_4.getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_1166
		and target_4.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_4.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_4.getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_4.getArgument(3).(VariableAccess).getTarget()=voff_1162
}

*/
predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_5.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_6(Parameter vclazz_1162, EqualityOperation target_6) {
		target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_6.getAnOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_6.getAnOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
}

predicate func_7(Variable vph32_1165, Variable vph64_1166, Parameter vclazz_1162, ConditionalExpr target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_1162
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_1165
		and target_7.getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_1166
}

from Function func, Parameter vfd_1162, Parameter voff_1162, Variable vph32_1165, Variable vph64_1166, Parameter vclazz_1162, UnaryMinusExpr target_3, BlockStmt target_5, EqualityOperation target_6, ConditionalExpr target_7
where
not func_0(vclazz_1162, target_5, target_6, target_7)
and func_3(vfd_1162, voff_1162, vph32_1165, vph64_1166, vclazz_1162, target_5, target_3)
and func_5(target_5)
and func_6(vclazz_1162, target_6)
and func_7(vph32_1165, vph64_1166, vclazz_1162, target_7)
and vfd_1162.getType().hasName("int")
and voff_1162.getType().hasName("off_t")
and vph32_1165.getType().hasName("Elf32_Phdr")
and vph64_1166.getType().hasName("Elf64_Phdr")
and vclazz_1162.getType().hasName("int")
and vfd_1162.getParentScope+() = func
and voff_1162.getParentScope+() = func
and vph32_1165.getParentScope+() = func
and vph64_1166.getParentScope+() = func
and vclazz_1162.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
