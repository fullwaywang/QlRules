/**
 * @name openssl-0042fb5fd1c9d257d713b15a1f45da05cf5c1c87-c2i_ASN1_OBJECT
 * @id cpp/openssl/0042fb5fd1c9d257d713b15a1f45da05cf5c1c87/c2i-ASN1-OBJECT
 * @description openssl-0042fb5fd1c9d257d713b15a1f45da05cf5c1c87-c2i_ASN1_OBJECT CVE-2014-3508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_6(Variable vret_293, Variable vdata_295, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_293
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_6.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdata_295
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_6.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_6))
}

predicate func_10(Variable vret_293, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_293
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_10))
}

predicate func_11(Variable vp_294, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_294
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_11))
}

predicate func_13(Function func) {
	exists(ReturnStmt target_13 |
		target_13.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_13))
}

predicate func_14(Variable vi_296) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(VariableAccess).getTarget()=vi_296
		and target_14.getRValue().(Literal).getValue()="0")
}

predicate func_15(Parameter vpp_290, Variable vp_294) {
	exists(AssignExpr target_15 |
		target_15.getLValue().(VariableAccess).getTarget()=vp_294
		and target_15.getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpp_290)
}

predicate func_20(Parameter vlen_291, Variable vret_293, Variable vdata_295, Variable vi_296) {
	exists(IfStmt target_20 |
		target_20.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_295
		and target_20.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_296
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getValue()="65"
		and target_20.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_295
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_293
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_291)
}

predicate func_21(Parameter vlen_291, Variable vret_293, Variable vdata_295) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_21.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_293
		and target_21.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_295
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_293
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_291)
}

predicate func_22(Parameter vlen_291, Variable vret_293) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="length"
		and target_22.getQualifier().(VariableAccess).getTarget()=vret_293
		and target_22.getParent().(AssignExpr).getLValue() = target_22
		and target_22.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_291)
}

predicate func_27(Function func) {
	exists(CommaExpr target_27 |
		target_27.getLeftOperand() instanceof AssignExpr
		and target_27.getRightOperand() instanceof AssignExpr
		and target_27.getEnclosingFunction() = func)
}

predicate func_28(Parameter vlen_291) {
	exists(ConditionalExpr target_28 |
		target_28.getCondition().(VariableAccess).getTarget()=vlen_291
		and target_28.getThen().(VariableAccess).getTarget()=vlen_291
		and target_28.getElse() instanceof Literal
		and target_28.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("CRYPTO_malloc")
		and target_28.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_28.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

from Function func, Parameter vpp_290, Parameter vlen_291, Variable vret_293, Variable vp_294, Variable vdata_295, Variable vi_296
where
not func_6(vret_293, vdata_295, func)
and not func_10(vret_293, func)
and not func_11(vp_294, func)
and not func_13(func)
and func_14(vi_296)
and func_15(vpp_290, vp_294)
and func_20(vlen_291, vret_293, vdata_295, vi_296)
and func_21(vlen_291, vret_293, vdata_295)
and func_22(vlen_291, vret_293)
and func_27(func)
and func_28(vlen_291)
and vpp_290.getType().hasName("const unsigned char **")
and vlen_291.getType().hasName("long")
and vret_293.getType().hasName("ASN1_OBJECT *")
and vp_294.getType().hasName("const unsigned char *")
and vdata_295.getType().hasName("unsigned char *")
and vi_296.getType().hasName("int")
and vpp_290.getParentScope+() = func
and vlen_291.getParentScope+() = func
and vret_293.getParentScope+() = func
and vp_294.getParentScope+() = func
and vdata_295.getParentScope+() = func
and vi_296.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
