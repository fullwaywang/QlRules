/**
 * @name libyang-4e610ccd87a2ba9413819777d508f71163fcc237-resolve_superior_type
 * @id cpp/libyang/4e610ccd87a2ba9413819777d508f71163fcc237/resolve-superior-type
 * @description libyang-4e610ccd87a2ba9413819777d508f71163fcc237-src/resolve.c-resolve_superior_type CVE-2019-20395
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(GTExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vmatch_3310, ExprStmt target_16, ValueFieldAccess target_17) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("resolve_superior_type_check")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_12, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vmodule_3306, Variable vi_3309, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="tpdf"
		and target_3.getQualifier().(VariableAccess).getTarget()=vmodule_3306
		and target_3.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
}

predicate func_4(Parameter vmodule_3306, Variable vi_3309, Variable vj_3309, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="tpdf"
		and target_4.getQualifier().(ValueFieldAccess).getTarget().getName()="submodule"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="inc"
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmodule_3306
		and target_4.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_4.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_3309
}

predicate func_5(Parameter vname_3306, Variable vi_3309, Variable vtpdf_3310, BlockStmt target_18, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_5.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_5.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtpdf_3310
		and target_5.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_5.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_3306
		and target_5.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_18
}

predicate func_6(Parameter vname_3306, Parameter vmodule_3306, Variable vi_3309, BlockStmt target_19, NotExpr target_6) {
		target_6.getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_6.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_6.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_6.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmodule_3306
		and target_6.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_6.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_3306
		and target_6.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_6.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_19
}

predicate func_7(Parameter vname_3306, Variable vj_3309, BlockStmt target_20, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_7.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="name"
		and target_7.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_7.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="submodule"
		and target_7.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_3309
		and target_7.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vname_3306
		and target_7.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_7.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_8(Variable vmatch_3310, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="type"
		and target_8.getQualifier().(VariableAccess).getTarget()=vmatch_3310
}

predicate func_9(Variable vi_3309, Variable vtpdf_3310, BlockStmt target_18, LogicalAndExpr target_9) {
		target_9.getAnOperand() instanceof NotExpr
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="base"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtpdf_3310
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_9.getParent().(IfStmt).getThen()=target_18
}

predicate func_10(Parameter vmodule_3306, Variable vi_3309, BlockStmt target_19, LogicalAndExpr target_10) {
		target_10.getAnOperand() instanceof NotExpr
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="base"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmodule_3306
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen()=target_19
}

predicate func_11(Variable vj_3309, BlockStmt target_20, LogicalAndExpr target_11) {
		target_11.getAnOperand() instanceof NotExpr
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="base"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="submodule"
		and target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_3309
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen()=target_20
}

predicate func_12(Variable vmatch_3310, BlockStmt target_21, EqualityOperation target_12) {
		target_12.getAnOperand().(ValueFieldAccess).getTarget().getName()="base"
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
		and target_12.getParent().(IfStmt).getThen()=target_21
}

predicate func_13(Variable vmatch_3310, EqualityOperation target_12, WhileStmt target_13) {
		target_13.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="path"
		and target_13.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="lref"
		and target_13.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="info"
		and target_13.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_3310
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="der"
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
		and target_13.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
}

/*predicate func_14(Variable vmatch_3310, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_3310
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="der"
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_14.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
}

*/
/*predicate func_15(Function func, ExprStmt target_15) {
		target_15.getExpr().(Literal).getValue()="0"
		and target_15.getEnclosingFunction() = func
}

*/
predicate func_16(Variable vmatch_3310, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vmatch_3310
}

predicate func_17(Variable vmatch_3310, ValueFieldAccess target_17) {
		target_17.getTarget().getName()="info"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmatch_3310
}

predicate func_18(Variable vi_3309, Variable vtpdf_3310, Variable vmatch_3310, BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_3310
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtpdf_3310
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_18.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_18.getStmt(1).(GotoStmt).getName() ="check_leafref"
}

predicate func_19(Parameter vmodule_3306, Variable vi_3309, Variable vmatch_3310, BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_3310
		and target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmodule_3306
		and target_19.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3309
		and target_19.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_19.getStmt(1).(GotoStmt).getName() ="check_leafref"
}

predicate func_20(Variable vj_3309, Variable vmatch_3310, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmatch_3310
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="submodule"
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_3309
		and target_20.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_20.getStmt(1).(GotoStmt).getName() ="check_leafref"
}

predicate func_21(BlockStmt target_21) {
		target_21.getStmt(0) instanceof WhileStmt
}

from Function func, Parameter vname_3306, Parameter vmodule_3306, Variable vi_3309, Variable vj_3309, Variable vtpdf_3310, Variable vmatch_3310, Literal target_0, PointerFieldAccess target_3, PointerFieldAccess target_4, NotExpr target_5, NotExpr target_6, NotExpr target_7, PointerFieldAccess target_8, LogicalAndExpr target_9, LogicalAndExpr target_10, LogicalAndExpr target_11, EqualityOperation target_12, WhileStmt target_13, ExprStmt target_16, ValueFieldAccess target_17, BlockStmt target_18, BlockStmt target_19, BlockStmt target_20, BlockStmt target_21
where
func_0(func, target_0)
and not func_1(vmatch_3310, target_16, target_17)
and not func_2(target_12, func)
and func_3(vmodule_3306, vi_3309, target_3)
and func_4(vmodule_3306, vi_3309, vj_3309, target_4)
and func_5(vname_3306, vi_3309, vtpdf_3310, target_18, target_5)
and func_6(vname_3306, vmodule_3306, vi_3309, target_19, target_6)
and func_7(vname_3306, vj_3309, target_20, target_7)
and func_8(vmatch_3310, target_8)
and func_9(vi_3309, vtpdf_3310, target_18, target_9)
and func_10(vmodule_3306, vi_3309, target_19, target_10)
and func_11(vj_3309, target_20, target_11)
and func_12(vmatch_3310, target_21, target_12)
and func_13(vmatch_3310, target_12, target_13)
and func_16(vmatch_3310, target_16)
and func_17(vmatch_3310, target_17)
and func_18(vi_3309, vtpdf_3310, vmatch_3310, target_18)
and func_19(vmodule_3306, vi_3309, vmatch_3310, target_19)
and func_20(vj_3309, vmatch_3310, target_20)
and func_21(target_21)
and vname_3306.getType().hasName("const char *")
and vmodule_3306.getType().hasName("const lys_module *")
and vi_3309.getType().hasName("int")
and vj_3309.getType().hasName("int")
and vtpdf_3310.getType().hasName("lys_tpdf *")
and vmatch_3310.getType().hasName("lys_tpdf *")
and vname_3306.getParentScope+() = func
and vmodule_3306.getParentScope+() = func
and vi_3309.getParentScope+() = func
and vj_3309.getParentScope+() = func
and vtpdf_3310.getParentScope+() = func
and vmatch_3310.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
