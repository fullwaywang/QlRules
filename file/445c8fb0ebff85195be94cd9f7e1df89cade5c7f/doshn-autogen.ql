/**
 * @name file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-doshn
 * @id cpp/file/445c8fb0ebff85195be94cd9f7e1df89cade5c7f/doshn
 * @description file-445c8fb0ebff85195be94cd9f7e1df89cade5c7f-src/readelf.c-doshn CVE-2014-9653
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofExprOperator target_0) {
		target_0.getValue()="50"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vclazz_919, BlockStmt target_21, EqualityOperation target_22, ConditionalExpr target_23) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand() instanceof FunctionCall
		and target_1.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_1.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_1.getGreaterOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_1.getGreaterOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_1.getParent().(IfStmt).getThen()=target_21
		and target_22.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_23.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vclazz_919, Parameter vswap_919, Parameter vfd_919, Variable vsh32_922, Variable vsh64_923, Variable vname_off_927, Variable vname_930, BlockStmt target_24, ExprStmt target_25, ConditionalExpr target_26, ValueFieldAccess target_29) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getType().hasName("ssize_t")
		and target_5.getRValue().(FunctionCall).getTarget().hasName("pread")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_5.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_930
		and target_5.getRValue().(FunctionCall).getArgument(2) instanceof SubExpr
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vname_off_927
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_930
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2) instanceof SizeofExprOperator
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vname_off_927
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_5.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_5.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_24
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_26.getThen().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_29.getQualifier().(VariableAccess).getLocation().isBefore(target_5.getRValue().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vclazz_919, BlockStmt target_30, AddExpr target_31, ConditionalExpr target_32) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand() instanceof FunctionCall
		and target_7.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_7.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getGreaterOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_7.getGreaterOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_7.getParent().(IfStmt).getThen()=target_30
		and target_31.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_7.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_32.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, BlockStmt target_33, ConditionalExpr target_34, ConditionalExpr target_35, ValueFieldAccess target_36, ValueFieldAccess target_37, ValueFieldAccess target_38, ValueFieldAccess target_39) {
	exists(RelationalOperation target_10 |
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand() instanceof FunctionCall
		and target_10.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_10.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
		and target_10.getParent().(IfStmt).getThen()=target_33
		and target_34.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_35.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_36.getQualifier().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_37.getQualifier().(VariableAccess).getLocation())
		and target_38.getQualifier().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vclazz_919, Parameter vfd_919, Parameter voff_919, Parameter vsize_920, Parameter vstrtab_920, Variable vsh32_922, Variable vsh64_923, BlockStmt target_21, UnaryMinusExpr target_13) {
		target_13.getValue()="-1"
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=voff_919
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_920
		and target_13.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstrtab_920
		and target_13.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_21
}

predicate func_14(BlockStmt target_24, Function func, UnaryMinusExpr target_14) {
		target_14.getValue()="-1"
		and target_14.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_24
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vname_930, SubExpr target_15) {
		target_15.getValue()="49"
		and target_15.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_930
}

predicate func_16(Parameter vclazz_919, Parameter vfd_919, Parameter voff_919, Variable vsh32_922, Variable vsh64_923, BlockStmt target_30, UnaryMinusExpr target_16) {
		target_16.getValue()="-1"
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_16.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voff_919
		and target_16.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_30
}

predicate func_17(Parameter vclazz_919, Parameter vswap_919, Parameter vfd_919, Variable vsh32_922, Variable vsh64_923, Variable vnbuf_926, BlockStmt target_33, UnaryMinusExpr target_17) {
		target_17.getValue()="-1"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("pread")
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnbuf_926
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_17.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
		and target_17.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_33
}

/*predicate func_18(Parameter vclazz_919, Parameter vfd_919, Parameter voff_919, Parameter vsize_920, Parameter vstrtab_920, Variable vsh32_922, Variable vsh64_923, FunctionCall target_18) {
		target_18.getTarget().hasName("pread")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_18.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_18.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_18.getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_18.getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
		and target_18.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_18.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_18.getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_18.getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_18.getArgument(3).(AddExpr).getAnOperand().(VariableAccess).getTarget()=voff_919
		and target_18.getArgument(3).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_920
		and target_18.getArgument(3).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstrtab_920
}

*/
/*predicate func_19(Parameter vclazz_919, Parameter vfd_919, Parameter voff_919, Variable vsh32_922, Variable vsh64_923, FunctionCall target_19) {
		target_19.getTarget().hasName("pread")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_19.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_19.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_19.getArgument(1).(ConditionalExpr).getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_19.getArgument(1).(ConditionalExpr).getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
		and target_19.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_19.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_19.getArgument(2).(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_19.getArgument(2).(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
		and target_19.getArgument(3).(VariableAccess).getTarget()=voff_919
}

*/
/*predicate func_20(Parameter vclazz_919, Parameter vswap_919, Parameter vfd_919, Variable vsh32_922, Variable vsh64_923, Variable vnbuf_926, FunctionCall target_20) {
		target_20.getTarget().hasName("pread")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vfd_919
		and target_20.getArgument(1).(VariableAccess).getTarget()=vnbuf_926
		and target_20.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_20.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_20.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_20.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_20.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_20.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_20.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_20.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_20.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_20.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
		and target_20.getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_20.getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_20.getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_20.getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_20.getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_20.getArgument(3).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_20.getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_20.getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_20.getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_20.getArgument(3).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

*/
predicate func_21(BlockStmt target_21) {
		target_21.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_21.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_22(Parameter vclazz_919, Parameter vsize_920, EqualityOperation target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vsize_920
		and target_22.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_22.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_22.getAnOperand().(ConditionalExpr).getThen().(SizeofExprOperator).getValue()="40"
		and target_22.getAnOperand().(ConditionalExpr).getElse().(SizeofExprOperator).getValue()="64"
}

predicate func_23(Parameter vclazz_919, Variable vsh32_922, Variable vsh64_923, ConditionalExpr target_23) {
		target_23.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_23.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_23.getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_23.getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
}

predicate func_24(BlockStmt target_24) {
		target_24.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_24.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_25(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, Variable vname_off_927, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_off_927
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_offset"
		and target_25.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_26(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, ConditionalExpr target_26) {
		target_26.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_26.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_26.getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_26.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_26.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_type"
		and target_26.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_26.getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_26.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_26.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_type"
		and target_26.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_29(Variable vsh64_923, ValueFieldAccess target_29) {
		target_29.getTarget().getName()="sh_offset"
		and target_29.getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_30(BlockStmt target_30) {
		target_30.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_30.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_31(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, Variable vname_off_927, AddExpr target_31) {
		target_31.getAnOperand().(VariableAccess).getTarget()=vname_off_927
		and target_31.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_31.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_31.getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_31.getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_31.getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_31.getAnOperand().(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_31.getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_31.getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_31.getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_name"
		and target_31.getAnOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_32(Parameter vclazz_919, Variable vsh32_922, Variable vsh64_923, ConditionalExpr target_32) {
		target_32.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_32.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_32.getThen().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh32_922
		and target_32.getElse().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsh64_923
}

predicate func_33(Variable vnbuf_926, BlockStmt target_33) {
		target_33.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("file_badread")
		and target_33.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_33.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnbuf_926
		and target_33.getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_34(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, ConditionalExpr target_34) {
		target_34.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_34.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_34.getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_34.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_34.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_34.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_34.getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_34.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_34.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_34.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_35(Parameter vclazz_919, Parameter vswap_919, Variable vsh32_922, Variable vsh64_923, ConditionalExpr target_35) {
		target_35.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclazz_919
		and target_35.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_35.getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_35.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_35.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_35.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh32_922
		and target_35.getElse().(FunctionCall).getTarget().hasName("getu64")
		and target_35.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vswap_919
		and target_35.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="sh_size"
		and target_35.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_36(Variable vsh32_922, ValueFieldAccess target_36) {
		target_36.getTarget().getName()="sh_size"
		and target_36.getQualifier().(VariableAccess).getTarget()=vsh32_922
}

predicate func_37(Variable vsh32_922, ValueFieldAccess target_37) {
		target_37.getTarget().getName()="sh_size"
		and target_37.getQualifier().(VariableAccess).getTarget()=vsh32_922
}

predicate func_38(Variable vsh64_923, ValueFieldAccess target_38) {
		target_38.getTarget().getName()="sh_size"
		and target_38.getQualifier().(VariableAccess).getTarget()=vsh64_923
}

predicate func_39(Variable vsh64_923, ValueFieldAccess target_39) {
		target_39.getTarget().getName()="sh_size"
		and target_39.getQualifier().(VariableAccess).getTarget()=vsh64_923
}

from Function func, Parameter vclazz_919, Parameter vswap_919, Parameter vfd_919, Parameter voff_919, Parameter vsize_920, Parameter vstrtab_920, Variable vsh32_922, Variable vsh64_923, Variable vnbuf_926, Variable vname_off_927, Variable vname_930, SizeofExprOperator target_0, UnaryMinusExpr target_13, UnaryMinusExpr target_14, SubExpr target_15, UnaryMinusExpr target_16, UnaryMinusExpr target_17, BlockStmt target_21, EqualityOperation target_22, ConditionalExpr target_23, BlockStmt target_24, ExprStmt target_25, ConditionalExpr target_26, ValueFieldAccess target_29, BlockStmt target_30, AddExpr target_31, ConditionalExpr target_32, BlockStmt target_33, ConditionalExpr target_34, ConditionalExpr target_35, ValueFieldAccess target_36, ValueFieldAccess target_37, ValueFieldAccess target_38, ValueFieldAccess target_39
where
func_0(func, target_0)
and not func_1(vclazz_919, target_21, target_22, target_23)
and not func_5(vclazz_919, vswap_919, vfd_919, vsh32_922, vsh64_923, vname_off_927, vname_930, target_24, target_25, target_26, target_29)
and not func_7(vclazz_919, target_30, target_31, target_32)
and not func_10(vclazz_919, vswap_919, vsh32_922, vsh64_923, target_33, target_34, target_35, target_36, target_37, target_38, target_39)
and func_13(vclazz_919, vfd_919, voff_919, vsize_920, vstrtab_920, vsh32_922, vsh64_923, target_21, target_13)
and func_14(target_24, func, target_14)
and func_15(vname_930, target_15)
and func_16(vclazz_919, vfd_919, voff_919, vsh32_922, vsh64_923, target_30, target_16)
and func_17(vclazz_919, vswap_919, vfd_919, vsh32_922, vsh64_923, vnbuf_926, target_33, target_17)
and func_21(target_21)
and func_22(vclazz_919, vsize_920, target_22)
and func_23(vclazz_919, vsh32_922, vsh64_923, target_23)
and func_24(target_24)
and func_25(vclazz_919, vswap_919, vsh32_922, vsh64_923, vname_off_927, target_25)
and func_26(vclazz_919, vswap_919, vsh32_922, vsh64_923, target_26)
and func_29(vsh64_923, target_29)
and func_30(target_30)
and func_31(vclazz_919, vswap_919, vsh32_922, vsh64_923, vname_off_927, target_31)
and func_32(vclazz_919, vsh32_922, vsh64_923, target_32)
and func_33(vnbuf_926, target_33)
and func_34(vclazz_919, vswap_919, vsh32_922, vsh64_923, target_34)
and func_35(vclazz_919, vswap_919, vsh32_922, vsh64_923, target_35)
and func_36(vsh32_922, target_36)
and func_37(vsh32_922, target_37)
and func_38(vsh64_923, target_38)
and func_39(vsh64_923, target_39)
and vclazz_919.getType().hasName("int")
and vswap_919.getType().hasName("int")
and vfd_919.getType().hasName("int")
and voff_919.getType().hasName("off_t")
and vsize_920.getType().hasName("size_t")
and vstrtab_920.getType().hasName("int")
and vsh32_922.getType().hasName("Elf32_Shdr")
and vsh64_923.getType().hasName("Elf64_Shdr")
and vnbuf_926.getType().hasName("void *")
and vname_off_927.getType().hasName("off_t")
and vname_930.getType().hasName("char[50]")
and vclazz_919.getParentScope+() = func
and vswap_919.getParentScope+() = func
and vfd_919.getParentScope+() = func
and voff_919.getParentScope+() = func
and vsize_920.getParentScope+() = func
and vstrtab_920.getParentScope+() = func
and vsh32_922.getParentScope+() = func
and vsh64_923.getParentScope+() = func
and vnbuf_926.getParentScope+() = func
and vname_off_927.getParentScope+() = func
and vname_930.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
