/**
 * @name libyang-7852b272ef77f8098c35deea6c6f09cb78176f08-lys_restr_dup
 * @id cpp/libyang/7852b272ef77f8098c35deea6c6f09cb78176f08/lys-restr-dup
 * @description libyang-7852b272ef77f8098c35deea6c6f09cb78176f08-src/tree_schema.c-lys_restr_dup CVE-2019-20398
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_1594, Parameter vunres_1591, Parameter vold_1591, PostfixIncrExpr target_3, ArrayExpr target_4, ExprStmt target_2, ArrayExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("unres_schema_find")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vunres_1591
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ext"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_1591
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_0.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_1594, Variable vresult_1593, Parameter vold_1591, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ext_size"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vresult_1593
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ext_size"
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_1591
		and target_1.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
}

predicate func_2(Variable vi_1594, Parameter vshallow_1591, Parameter vunres_1591, Variable vresult_1593, Parameter vmod_1591, Parameter vold_1591, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("lys_ext_dup")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmod_1591
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmod_1591
		and target_2.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="ext"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_1591
		and target_2.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_2.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="ext_size"
		and target_2.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_1591
		and target_2.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_2.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vresult_1593
		and target_2.getExpr().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_2.getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ext"
		and target_2.getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vresult_1593
		and target_2.getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1594
		and target_2.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vshallow_1591
		and target_2.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vunres_1591
}

predicate func_3(Variable vi_1594, PostfixIncrExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vi_1594
}

predicate func_4(Variable vi_1594, Variable vresult_1593, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vresult_1593
		and target_4.getArrayOffset().(VariableAccess).getTarget()=vi_1594
}

predicate func_5(Variable vi_1594, Parameter vold_1591, ArrayExpr target_5) {
		target_5.getArrayBase().(VariableAccess).getTarget()=vold_1591
		and target_5.getArrayOffset().(VariableAccess).getTarget()=vi_1594
}

from Function func, Variable vi_1594, Parameter vshallow_1591, Parameter vunres_1591, Variable vresult_1593, Parameter vmod_1591, Parameter vold_1591, ExprStmt target_1, ExprStmt target_2, PostfixIncrExpr target_3, ArrayExpr target_4, ArrayExpr target_5
where
not func_0(vi_1594, vunres_1591, vold_1591, target_3, target_4, target_2, target_5)
and func_1(vi_1594, vresult_1593, vold_1591, target_1)
and func_2(vi_1594, vshallow_1591, vunres_1591, vresult_1593, vmod_1591, vold_1591, target_2)
and func_3(vi_1594, target_3)
and func_4(vi_1594, vresult_1593, target_4)
and func_5(vi_1594, vold_1591, target_5)
and vi_1594.getType().hasName("int")
and vshallow_1591.getType().hasName("int")
and vunres_1591.getType().hasName("unres_schema *")
and vresult_1593.getType().hasName("lys_restr *")
and vmod_1591.getType().hasName("lys_module *")
and vold_1591.getType().hasName("lys_restr *")
and vi_1594.getParentScope+() = func
and vshallow_1591.getParentScope+() = func
and vunres_1591.getParentScope+() = func
and vresult_1593.getParentScope+() = func
and vmod_1591.getParentScope+() = func
and vold_1591.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
