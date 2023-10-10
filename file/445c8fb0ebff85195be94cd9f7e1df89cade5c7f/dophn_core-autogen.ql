/**
 * @name file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-dophn_core
 * @id cpp/file/445c8fb0ebff85195be94cd9f7e1df89cade5c7f/dophn-core
 * @description file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-src/readelf.c-dophn_core CVE-2014-9653
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vclazz_303, BlockStmt target_5, EqualityOperation target_6, ConditionalExpr target_7) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof FunctionCall
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getGreaterOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_0.getGreaterOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vclazz_303, Parameter vfd_303, Parameter voff_303, Variable vph32_306, Variable vph64_307, BlockStmt target_5, UnaryMinusExpr target_3) {
		target_3.getValue()="-1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_303
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_306
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_307
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voff_303
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
}

/*predicate func_4(Parameter vclazz_303, Parameter vfd_303, Parameter voff_303, Variable vph32_306, Variable vph64_307, FunctionCall target_4) {
		target_4.getTarget().hasName("pread")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vfd_303
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_4.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_306
		and target_4.getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_307
		and target_4.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_4.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_4.getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
		and target_4.getArgument(3).(VariableAccess).getTarget()=voff_303
}

*/
predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_5.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_6(Parameter vclazz_303, EqualityOperation target_6) {
		target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_6.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_6.getAnOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="32"
		and target_6.getAnOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="56"
}

predicate func_7(Parameter vclazz_303, Variable vph32_306, Variable vph64_307, ConditionalExpr target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_303
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph32_306
		and target_7.getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vph64_307
}

from Function func, Parameter vclazz_303, Parameter vfd_303, Parameter voff_303, Variable vph32_306, Variable vph64_307, UnaryMinusExpr target_3, BlockStmt target_5, EqualityOperation target_6, ConditionalExpr target_7
where
not func_0(vclazz_303, target_5, target_6, target_7)
and func_3(vclazz_303, vfd_303, voff_303, vph32_306, vph64_307, target_5, target_3)
and func_5(target_5)
and func_6(vclazz_303, target_6)
and func_7(vclazz_303, vph32_306, vph64_307, target_7)
and vclazz_303.getType().hasName("int")
and vfd_303.getType().hasName("int")
and voff_303.getType().hasName("off_t")
and vph32_306.getType().hasName("Elf32_Phdr")
and vph64_307.getType().hasName("Elf64_Phdr")
and vclazz_303.getParentScope+() = func
and vfd_303.getParentScope+() = func
and voff_303.getParentScope+() = func
and vph32_306.getParentScope+() = func
and vph64_307.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
