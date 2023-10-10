/**
 * @name postgresql-2062007-LookupTypeName
 * @id cpp/postgresql/2062007/LookupTypeName
 * @description postgresql-2062007-src/backend/parser/parse_type.c-LookupTypeName CVE-2019-10208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtypeName_57, Parameter vtypmod_p_58, Parameter vmissing_ok_58, Parameter vpstate_57, EqualityOperation target_76, IfStmt target_45, FunctionCall target_78) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("LookupTypeNameExtended")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_0.getArgument(1).(VariableAccess).getTarget()=vtypeName_57
		and target_0.getArgument(2).(VariableAccess).getTarget()=vtypmod_p_58
		and target_0.getArgument(3) instanceof Literal
		and target_0.getArgument(4).(VariableAccess).getTarget()=vmissing_ok_58
		and target_76.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(4).(VariableAccess).getLocation().isBefore(target_45.getCondition().(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_78.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpstate_57, VariableAccess target_1) {
		target_1.getTarget()=vpstate_57
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall
}

predicate func_2(Parameter vtypeName_57, VariableAccess target_2) {
		target_2.getTarget()=vtypeName_57
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Parameter vmissing_ok_58, VariableAccess target_4) {
		target_4.getTarget()=vmissing_ok_58
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Parameter vtypmod_p_58, ExprStmt target_79, VariableAccess target_5) {
		target_5.getTarget()=vtypmod_p_58
		and target_5.getParent().(IfStmt).getThen()=target_79
}

predicate func_6(Function func, DeclStmt target_6) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Function func, DeclStmt target_7) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Function func, DeclStmt target_8) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Parameter vtypeName_57, Parameter vmissing_ok_58, Variable vtypoid_60, Variable vrel_72, Variable vfield_73, Variable vrelid_74, Variable vattnum_75, Variable vschemaname_148, Variable vtypname_149, Function func, IfStmt target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="names"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="typeOid"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_9.getElse().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="pct_type"
		and target_9.getElse().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(FunctionCall).getTarget().hasName("list_length")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(18).(SwitchCase).toString() = "default: "
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrelid_74
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RangeVarGetRelidExtended")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_72
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmissing_ok_58
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_75
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_attnum")
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelid_74
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_73
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vattnum_75
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vmissing_ok_58
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_9.getElse().(IfStmt).getThen().(BlockStmt).getStmt(7).(IfStmt).getElse().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("DeconstructQualifiedName")
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vschemaname_148
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtypname_149
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getTarget()=vschemaname_148
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setup_parser_errposition_callback")
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cancel_parser_errposition_callback")
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="arrayBounds"
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_9.getElse().(IfStmt).getElse().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_array_type")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

/*predicate func_10(Parameter vtypeName_57, Variable vtypoid_60, EqualityOperation target_80, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="typeOid"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_80
}

*/
predicate func_11(PointerFieldAccess target_81, Function func, DeclStmt target_11) {
		target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
		and target_11.getEnclosingFunction() = func
}

predicate func_12(PointerFieldAccess target_81, Function func, DeclStmt target_12) {
		target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
		and target_12.getEnclosingFunction() = func
}

predicate func_13(PointerFieldAccess target_81, Function func, DeclStmt target_13) {
		target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
		and target_13.getEnclosingFunction() = func
}

predicate func_14(PointerFieldAccess target_81, Function func, DeclStmt target_14) {
		target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
		and target_14.getEnclosingFunction() = func
}

/*predicate func_15(Parameter vtypeName_57, Variable vrel_72, Variable vfield_73, Variable v__func__, SwitchStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("list_length")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_15.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr() instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_15.getStmt().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_15.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_15.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(7).(SwitchCase).getExpr().(Literal).getValue()="3"
		and target_15.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="schemaname"
		and target_15.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_15.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_15.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(10).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(12).(SwitchCase).getExpr().(Literal).getValue()="4"
		and target_15.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="catalogname"
		and target_15.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(13).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="schemaname"
		and target_15.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(14).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(15).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_15.getStmt().(BlockStmt).getStmt(15).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_15.getStmt().(BlockStmt).getStmt(15).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(15).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(15).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_15.getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_15.getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_15.getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_15.getStmt().(BlockStmt).getStmt(18).(SwitchCase).toString() = "default: "
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getCondition() instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_15.getStmt().(BlockStmt).getStmt(19).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

*/
/*predicate func_16(Function func, SwitchCase target_16) {
		target_16.getExpr() instanceof Literal
		and target_16.getEnclosingFunction() = func
}

*/
/*predicate func_17(Variable v__func__, Parameter vpstate_57, FunctionCall target_82, DoStmt target_17) {
		target_17.getCondition() instanceof Literal
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="improper %%TYPE reference (too few dotted names): %s"
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("NameListToString")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_17.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_17.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_17.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_18(Parameter vtypeName_57, Variable v__func__, Parameter vpstate_57, IfStmt target_18) {
		target_18.getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_18.getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_18.getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_18.getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddExpr).getValue()="16801924"
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="improper %%TYPE reference (too few dotted names): %s"
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("NameListToString")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

*/
/*predicate func_19(Function func, IfStmt target_19) {
		target_19.getCondition().(LogicalAndExpr).getValue()="1"
		and target_19.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_19.getEnclosingFunction() = func
}

*/
/*predicate func_20(FunctionCall target_82, Function func, BreakStmt target_20) {
		target_20.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
		and target_20.getEnclosingFunction() = func
}

*/
/*predicate func_21(Function func, SwitchCase target_21) {
		target_21.getExpr().(Literal).getValue()="2"
		and target_21.getEnclosingFunction() = func
}

*/
/*predicate func_22(Variable vrel_72, FunctionCall target_82, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_22.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("list_head")
		and target_22.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_23(Variable vfield_73, FunctionCall target_82, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_23.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_24(FunctionCall target_82, Function func, BreakStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
		and target_24.getEnclosingFunction() = func
}

*/
/*predicate func_25(Function func, SwitchCase target_25) {
		target_25.getExpr().(Literal).getValue()="3"
		and target_25.getEnclosingFunction() = func
}

*/
/*predicate func_26(Variable vrel_72, FunctionCall target_82, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="schemaname"
		and target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_26.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("list_head")
		and target_26.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_27(Variable vrel_72, FunctionCall target_82, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_27.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_27.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_28(Variable vfield_73, FunctionCall target_82, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_28.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_28.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_29(FunctionCall target_82, Function func, BreakStmt target_29) {
		target_29.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
		and target_29.getEnclosingFunction() = func
}

*/
/*predicate func_30(Function func, SwitchCase target_30) {
		target_30.getExpr().(Literal).getValue()="4"
		and target_30.getEnclosingFunction() = func
}

*/
/*predicate func_31(Variable vrel_72, FunctionCall target_82, ExprStmt target_31) {
		target_31.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="catalogname"
		and target_31.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_31.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("list_head")
		and target_31.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_32(Variable vrel_72, FunctionCall target_82, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="schemaname"
		and target_32.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_32.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_32.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_33(Variable vrel_72, FunctionCall target_82, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relname"
		and target_33.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_33.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_33.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_33.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_33.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_33.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_33.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_34(Variable vfield_73, FunctionCall target_82, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_73
		and target_34.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="str"
		and target_34.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="val"
		and target_34.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ptr_value"
		and target_34.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_34.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_34.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_35(FunctionCall target_82, Function func, BreakStmt target_35) {
		target_35.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
		and target_35.getEnclosingFunction() = func
}

*/
/*predicate func_36(Function func, SwitchCase target_36) {
		target_36.toString() = "default: "
		and target_36.getEnclosingFunction() = func
}

*/
/*predicate func_37(Variable v__func__, Parameter vpstate_57, FunctionCall target_82, DoStmt target_37) {
		target_37.getCondition() instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="improper %%TYPE reference (too many dotted names): %s"
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("NameListToString")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_37.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_37.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_37.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_37.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
}

*/
/*predicate func_38(Parameter vtypeName_57, Variable v__func__, Parameter vpstate_57, IfStmt target_38) {
		target_38.getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_38.getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_38.getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_38.getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_38.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_38.getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddExpr).getValue()="16801924"
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="improper %%TYPE reference (too many dotted names): %s"
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("NameListToString")
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_38.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

*/
/*predicate func_39(Function func, IfStmt target_39) {
		target_39.getCondition().(LogicalAndExpr).getValue()="1"
		and target_39.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_39.getEnclosingFunction() = func
}

*/
/*predicate func_40(FunctionCall target_82, Function func, BreakStmt target_40) {
		target_40.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_82
		and target_40.getEnclosingFunction() = func
}

*/
/*predicate func_42(Parameter vmissing_ok_58, Variable vrel_72, Variable vrelid_74, PointerFieldAccess target_81, ExprStmt target_42) {
		target_42.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrelid_74
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RangeVarGetRelidExtended")
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_72
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmissing_ok_58
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_42.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_42.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
}

*/
/*predicate func_43(Variable vfield_73, Variable vrelid_74, Variable vattnum_75, PointerFieldAccess target_81, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattnum_75
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_attnum")
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelid_74
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_73
		and target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
}

*/
/*predicate func_44(Parameter vmissing_ok_58, Variable vtypoid_60, Variable vrelid_74, Variable vattnum_75, Variable v__func__, PointerFieldAccess target_81, IfStmt target_44) {
		target_44.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vattnum_75
		and target_44.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vmissing_ok_58
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_44.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_44.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_atttype")
		and target_44.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelid_74
		and target_44.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vattnum_75
		and target_44.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="0"
		and target_44.getElse().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_81
}

*/
predicate func_45(Parameter vmissing_ok_58, Variable vtypoid_60, Variable v__func__, IfStmt target_45) {
		target_45.getCondition().(VariableAccess).getTarget()=vmissing_ok_58
		and target_45.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_45.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_45.getElse().(DoStmt).getCondition() instanceof Literal
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_45.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

/*predicate func_46(Parameter vtypeName_57, Variable vrel_72, Variable vfield_73, Variable v__func__, Parameter vpstate_57, IfStmt target_46) {
		target_46.getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_46.getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_46.getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_46.getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_46.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_46.getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(AddExpr).getValue()="50360452"
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="column \"%s\" of relation \"%s\" does not exist"
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_73
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="relname"
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrel_72
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("parser_errposition")
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_46.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

*/
/*predicate func_47(Function func, IfStmt target_47) {
		target_47.getCondition().(LogicalAndExpr).getValue()="1"
		and target_47.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_47.getEnclosingFunction() = func
}

*/
/*predicate func_48(Variable vtypoid_60, Variable vrelid_74, Variable vattnum_75, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_48.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_atttype")
		and target_48.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrelid_74
		and target_48.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vattnum_75
}

*/
/*predicate func_49(Function func, ExprStmt target_49) {
		target_49.getExpr().(Literal).getValue()="1"
		and target_49.getEnclosingFunction() = func
}

*/
/*predicate func_50(Variable v__func__, DoStmt target_50) {
		target_50.getCondition() instanceof Literal
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errmsg")
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="type reference %s converted to %s"
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TypeNameToString")
		and target_50.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("format_type_be")
		and target_50.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="0"
		and target_50.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

*/
/*predicate func_51(Parameter vtypeName_57, Variable vtypoid_60, Variable v__func__, IfStmt target_51) {
		target_51.getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_51.getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_51.getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_51.getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_51.getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_51.getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errmsg")
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="type reference %s converted to %s"
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TypeNameToString")
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypeName_57
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("format_type_be")
		and target_51.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypoid_60
}

*/
/*predicate func_52(Function func, IfStmt target_52) {
		target_52.getCondition().(LogicalAndExpr).getValue()="0"
		and target_52.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_52.getEnclosingFunction() = func
}

*/
/*predicate func_55(Parameter vtypeName_57, Variable vschemaname_148, Variable vtypname_149, ExprStmt target_55) {
		target_55.getExpr().(FunctionCall).getTarget().hasName("DeconstructQualifiedName")
		and target_55.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_55.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_55.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vschemaname_148
		and target_55.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtypname_149
}

*/
/*predicate func_56(Variable vpcbstate_158, Parameter vtypeName_57, Parameter vmissing_ok_58, Variable vtypoid_60, Variable vschemaname_148, Variable vtypname_149, Variable vnamespaceId_157, Parameter vpstate_57, IfStmt target_56) {
		target_56.getCondition().(VariableAccess).getTarget()=vschemaname_148
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("setup_parser_errposition_callback")
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpcbstate_158
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstate_57
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="location"
		and target_56.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_56.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnamespaceId_157
		and target_56.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupExplicitNamespace")
		and target_56.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaname_148
		and target_56.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmissing_ok_58
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnamespaceId_157
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtypname_149
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_56.getThen().(BlockStmt).getStmt(4).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_56.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("cancel_parser_errposition_callback")
		and target_56.getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpcbstate_158
		and target_56.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_56.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TypenameGetTypid")
		and target_56.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypname_149
}

*/
/*predicate func_59(Variable vpcbstate_158, Parameter vtypeName_57, Parameter vpstate_57, ExprStmt target_59) {
		target_59.getExpr().(FunctionCall).getTarget().hasName("setup_parser_errposition_callback")
		and target_59.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpcbstate_158
		and target_59.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstate_57
		and target_59.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="location"
		and target_59.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

*/
/*predicate func_60(Parameter vmissing_ok_58, Variable vschemaname_148, Variable vnamespaceId_157, ExprStmt target_60) {
		target_60.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnamespaceId_157
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("LookupExplicitNamespace")
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaname_148
		and target_60.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmissing_ok_58
}

*/
/*predicate func_61(Variable vtypoid_60, Variable vtypname_149, Variable vnamespaceId_157, IfStmt target_61) {
		target_61.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnamespaceId_157
		and target_61.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetSysCacheOid")
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtypname_149
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vnamespaceId_157
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_61.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_61.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_61.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
/*predicate func_62(Variable vpcbstate_158, ExprStmt target_62) {
		target_62.getExpr().(FunctionCall).getTarget().hasName("cancel_parser_errposition_callback")
		and target_62.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vpcbstate_158
}

*/
/*predicate func_63(Variable vtypoid_60, Variable vtypname_149, ExprStmt target_63) {
		target_63.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_63.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TypenameGetTypid")
		and target_63.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypname_149
}

*/
/*predicate func_64(Parameter vtypeName_57, Variable vtypoid_60, IfStmt target_64) {
		target_64.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="arrayBounds"
		and target_64.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_64.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_64.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypoid_60
		and target_64.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_array_type")
		and target_64.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtypoid_60
}

*/
predicate func_65(Parameter vtypmod_p_58, Variable vtypoid_60, IfStmt target_65) {
		target_65.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtypoid_60
		and target_65.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vtypmod_p_58
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtypmod_p_58
		and target_65.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_65.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

/*predicate func_66(Parameter vtypmod_p_58, IfStmt target_66) {
		target_66.getCondition().(VariableAccess).getTarget()=vtypmod_p_58
		and target_66.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtypmod_p_58
		and target_66.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
}

*/
predicate func_68(Variable vtypoid_60, Variable vtup_61, ExprStmt target_68) {
		target_68.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtup_61
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SearchSysCache")
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vtypoid_60
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294967295"
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_68.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_69(Variable vtypoid_60, Variable vtup_61, Variable v__func__, IfStmt target_69) {
		target_69.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtup_61
		and target_69.getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_69.getThen().(DoStmt).getCondition() instanceof Literal
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("elog_start")
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("elog_finish")
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="cache lookup failed for type %u"
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypoid_60
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_69.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

/*predicate func_70(Variable v__func__, ExprStmt target_70) {
		target_70.getExpr().(FunctionCall).getTarget().hasName("elog_start")
		and target_70.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_70.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_70.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
}

*/
/*predicate func_71(Variable vtypoid_60, ExprStmt target_71) {
		target_71.getExpr().(FunctionCall).getTarget().hasName("elog_finish")
		and target_71.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_71.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="cache lookup failed for type %u"
		and target_71.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtypoid_60
}

*/
/*predicate func_72(Function func, IfStmt target_72) {
		target_72.getCondition().(LogicalAndExpr).getValue()="1"
		and target_72.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_72.getEnclosingFunction() = func
}

*/
predicate func_73(Parameter vtypeName_57, Variable vtup_61, Variable vtypmod_62, Parameter vpstate_57, ExprStmt target_73) {
		target_73.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtypmod_62
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("typenameTypeMod")
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtypeName_57
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtup_61
}

predicate func_74(Parameter vtypmod_p_58, Variable vtypmod_62, IfStmt target_74) {
		target_74.getCondition().(VariableAccess).getTarget()=vtypmod_p_58
		and target_74.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtypmod_p_58
		and target_74.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtypmod_62
}

predicate func_75(Variable vtup_61, ReturnStmt target_75) {
		target_75.getExpr().(VariableAccess).getTarget()=vtup_61
}

predicate func_76(Parameter vtypeName_57, EqualityOperation target_76) {
		target_76.getAnOperand().(PointerFieldAccess).getTarget().getName()="arrayBounds"
		and target_76.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_76.getAnOperand() instanceof Literal
}

predicate func_78(Parameter vtypeName_57, Parameter vpstate_57, FunctionCall target_78) {
		target_78.getTarget().hasName("parser_errposition")
		and target_78.getArgument(0).(VariableAccess).getTarget()=vpstate_57
		and target_78.getArgument(1).(PointerFieldAccess).getTarget().getName()="location"
		and target_78.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

predicate func_79(ExprStmt target_79) {
		target_79.getExpr() instanceof AssignExpr
}

predicate func_80(Parameter vtypeName_57, EqualityOperation target_80) {
		target_80.getAnOperand().(PointerFieldAccess).getTarget().getName()="names"
		and target_80.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
		and target_80.getAnOperand() instanceof Literal
}

predicate func_81(Parameter vtypeName_57, PointerFieldAccess target_81) {
		target_81.getTarget().getName()="pct_type"
		and target_81.getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

predicate func_82(Parameter vtypeName_57, FunctionCall target_82) {
		target_82.getTarget().hasName("list_length")
		and target_82.getArgument(0).(PointerFieldAccess).getTarget().getName()="names"
		and target_82.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypeName_57
}

from Function func, Variable vpcbstate_158, Parameter vtypeName_57, Parameter vtypmod_p_58, Parameter vmissing_ok_58, Variable vtypoid_60, Variable vtup_61, Variable vtypmod_62, Variable vrel_72, Variable vfield_73, Variable vrelid_74, Variable vattnum_75, Variable v__func__, Variable vschemaname_148, Variable vtypname_149, Variable vnamespaceId_157, Parameter vpstate_57, VariableAccess target_1, VariableAccess target_2, VariableAccess target_4, VariableAccess target_5, DeclStmt target_6, DeclStmt target_7, DeclStmt target_8, IfStmt target_9, DeclStmt target_11, DeclStmt target_12, DeclStmt target_13, DeclStmt target_14, IfStmt target_45, IfStmt target_65, ExprStmt target_68, IfStmt target_69, ExprStmt target_73, IfStmt target_74, ReturnStmt target_75, EqualityOperation target_76, FunctionCall target_78, ExprStmt target_79, EqualityOperation target_80, PointerFieldAccess target_81, FunctionCall target_82
where
not func_0(vtypeName_57, vtypmod_p_58, vmissing_ok_58, vpstate_57, target_76, target_45, target_78)
and func_1(vpstate_57, target_1)
and func_2(vtypeName_57, target_2)
and func_4(vmissing_ok_58, target_4)
and func_5(vtypmod_p_58, target_79, target_5)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and func_9(vtypeName_57, vmissing_ok_58, vtypoid_60, vrel_72, vfield_73, vrelid_74, vattnum_75, vschemaname_148, vtypname_149, func, target_9)
and func_11(target_81, func, target_11)
and func_12(target_81, func, target_12)
and func_13(target_81, func, target_13)
and func_14(target_81, func, target_14)
and func_45(vmissing_ok_58, vtypoid_60, v__func__, target_45)
and func_65(vtypmod_p_58, vtypoid_60, target_65)
and func_68(vtypoid_60, vtup_61, target_68)
and func_69(vtypoid_60, vtup_61, v__func__, target_69)
and func_73(vtypeName_57, vtup_61, vtypmod_62, vpstate_57, target_73)
and func_74(vtypmod_p_58, vtypmod_62, target_74)
and func_75(vtup_61, target_75)
and func_76(vtypeName_57, target_76)
and func_78(vtypeName_57, vpstate_57, target_78)
and func_79(target_79)
and func_80(vtypeName_57, target_80)
and func_81(vtypeName_57, target_81)
and func_82(vtypeName_57, target_82)
and vpcbstate_158.getType().hasName("ParseCallbackState")
and vtypeName_57.getType().hasName("const TypeName *")
and vtypmod_p_58.getType().hasName("int32 *")
and vmissing_ok_58.getType().hasName("bool")
and vtypoid_60.getType().hasName("Oid")
and vtup_61.getType().hasName("HeapTuple")
and vtypmod_62.getType().hasName("int32")
and vrel_72.getType().hasName("RangeVar *")
and vfield_73.getType().hasName("char *")
and vrelid_74.getType().hasName("Oid")
and vattnum_75.getType().hasName("AttrNumber")
and v__func__.getType() instanceof ArrayType
and vschemaname_148.getType().hasName("char *")
and vtypname_149.getType().hasName("char *")
and vnamespaceId_157.getType().hasName("Oid")
and vpstate_57.getType().hasName("ParseState *")
and vpcbstate_158.(LocalVariable).getFunction() = func
and vtypeName_57.getFunction() = func
and vtypmod_p_58.getFunction() = func
and vmissing_ok_58.getFunction() = func
and vtypoid_60.(LocalVariable).getFunction() = func
and vtup_61.(LocalVariable).getFunction() = func
and vtypmod_62.(LocalVariable).getFunction() = func
and vrel_72.(LocalVariable).getFunction() = func
and vfield_73.(LocalVariable).getFunction() = func
and vrelid_74.(LocalVariable).getFunction() = func
and vattnum_75.(LocalVariable).getFunction() = func
and not v__func__.getParentScope+() = func
and vschemaname_148.(LocalVariable).getFunction() = func
and vtypname_149.(LocalVariable).getFunction() = func
and vnamespaceId_157.(LocalVariable).getFunction() = func
and vpstate_57.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
