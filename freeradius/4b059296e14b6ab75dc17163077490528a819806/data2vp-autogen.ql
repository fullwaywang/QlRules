/**
 * @name freeradius-4b059296e14b6ab75dc17163077490528a819806-data2vp
 * @id cpp/freeradius/4b059296e14b6ab75dc17163077490528a819806/data2vp
 * @description freeradius-4b059296e14b6ab75dc17163077490528a819806-src/lib/radius.c-data2vp CVE-2017-10984
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="3821"
		and not target_0.getValue()="3894"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Internal sanity check %d"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="3901"
		and not target_1.getValue()="3961"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Internal sanity check %d"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="4027"
		and not target_2.getValue()="4087"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fr_strerror_printf")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="Internal sanity check %d"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vrcode_3530, EqualityOperation target_8, IfStmt target_3) {
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrcode_3530
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(GotoStmt).getName() ="raw"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_4(Parameter vpacket_3522, Parameter voriginal_3522, Parameter vsecret_3523, Parameter vattrlen_3525, Parameter vpvp_3526, Variable vrcode_3530, Variable vchild_3532, Variable vdata_3534, Parameter vctx_3521, PointerFieldAccess target_9, IfStmt target_4) {
		target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_3534
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="128"
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrcode_3530
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3521
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3522
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3522
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3523
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vchild_3532
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3534
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3525
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3525
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3526
		and target_4.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_4.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrcode_3530
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_9
}

/*predicate func_5(Parameter vpacket_3522, Parameter voriginal_3522, Parameter vsecret_3523, Parameter vattrlen_3525, Parameter vpvp_3526, Variable vrcode_3530, Variable vchild_3532, Variable vdata_3534, Parameter vctx_3521, EqualityOperation target_8, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrcode_3530
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3521
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3522
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3522
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3523
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vchild_3532
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdata_3534
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3525
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrlen_3525
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vpvp_3526
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
/*predicate func_6(Variable vrcode_3530, EqualityOperation target_8, ReturnStmt target_6) {
		target_6.getExpr().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_6.getExpr().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrcode_3530
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
predicate func_7(Variable vrcode_3530, PointerFieldAccess target_9, ExprStmt target_10, ReturnStmt target_11, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrcode_3530
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_7.getThen().(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(GotoStmt).getName() ="raw"
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(VariableAccess).getLocation())
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand() instanceof BitwiseAndExpr
		and target_8.getAnOperand() instanceof Literal
}

predicate func_9(PointerFieldAccess target_9) {
		target_9.getTarget().getName()="type"
}

predicate func_10(Parameter vpacket_3522, Parameter voriginal_3522, Parameter vsecret_3523, Parameter vattrlen_3525, Parameter vpvp_3526, Variable vrcode_3530, Variable vdata_3534, Parameter vctx_3521, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrcode_3530
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("data2vp_vsas")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_3521
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpacket_3522
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voriginal_3522
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vsecret_3523
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdata_3534
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vattrlen_3525
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vpvp_3526
}

predicate func_11(Variable vrcode_3530, ReturnStmt target_11) {
		target_11.getExpr().(VariableAccess).getTarget()=vrcode_3530
}

from Function func, Parameter vpacket_3522, Parameter voriginal_3522, Parameter vsecret_3523, Parameter vattrlen_3525, Parameter vpvp_3526, Variable vrcode_3530, Variable vchild_3532, Variable vdata_3534, Parameter vctx_3521, Literal target_0, Literal target_1, Literal target_2, IfStmt target_3, IfStmt target_4, IfStmt target_7, EqualityOperation target_8, PointerFieldAccess target_9, ExprStmt target_10, ReturnStmt target_11
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(vrcode_3530, target_8, target_3)
and func_4(vpacket_3522, voriginal_3522, vsecret_3523, vattrlen_3525, vpvp_3526, vrcode_3530, vchild_3532, vdata_3534, vctx_3521, target_9, target_4)
and func_7(vrcode_3530, target_9, target_10, target_11, target_7)
and func_8(target_8)
and func_9(target_9)
and func_10(vpacket_3522, voriginal_3522, vsecret_3523, vattrlen_3525, vpvp_3526, vrcode_3530, vdata_3534, vctx_3521, target_10)
and func_11(vrcode_3530, target_11)
and vpacket_3522.getType().hasName("RADIUS_PACKET *")
and voriginal_3522.getType().hasName("const RADIUS_PACKET *")
and vsecret_3523.getType().hasName("const char *")
and vattrlen_3525.getType().hasName("const size_t")
and vpvp_3526.getType().hasName("VALUE_PAIR **")
and vrcode_3530.getType().hasName("ssize_t")
and vchild_3532.getType().hasName("const DICT_ATTR *")
and vdata_3534.getType().hasName("const uint8_t *")
and vctx_3521.getType().hasName("TALLOC_CTX *")
and vpacket_3522.getParentScope+() = func
and voriginal_3522.getParentScope+() = func
and vsecret_3523.getParentScope+() = func
and vattrlen_3525.getParentScope+() = func
and vpvp_3526.getParentScope+() = func
and vrcode_3530.getParentScope+() = func
and vchild_3532.getParentScope+() = func
and vdata_3534.getParentScope+() = func
and vctx_3521.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
