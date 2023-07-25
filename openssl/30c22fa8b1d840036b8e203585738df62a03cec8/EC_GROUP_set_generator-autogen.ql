/**
 * @name openssl-30c22fa8b1d840036b8e203585738df62a03cec8-EC_GROUP_set_generator
 * @id cpp/openssl/30c22fa8b1d840036b8e203585738df62a03cec8/EC-GROUP-set-generator
 * @description openssl-30c22fa8b1d840036b8e203585738df62a03cec8-crypto/ec/ec_lib.c-EC_GROUP_set_generator CVE-2019-1547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vorder_269, BlockStmt target_15, NotExpr target_16, VariableAccess target_0) {
		target_0.getTarget()=vorder_269
		and target_0.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_15
		and target_0.getLocation().isBefore(target_16.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_1(Parameter vgroup_268, FunctionCall target_1) {
		target_1.getTarget().hasName("BN_set_word")
		and not target_1.getTarget().hasName("BN_is_zero")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="order"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_1.getArgument(1) instanceof Literal
}

predicate func_2(Parameter vgroup_268, BlockStmt target_15, NotExpr target_16) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="field"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_2.getParent().(IfStmt).getThen()=target_15
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vgroup_268, NotExpr target_16) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="field"
		and target_3.getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_16.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ERR_put_error")
		and target_4.getArgument(0).(Literal).getValue()="16"
		and target_4.getArgument(1).(Literal).getValue()="111"
		and target_4.getArgument(2).(Literal).getValue()="103"
		and target_4.getArgument(3) instanceof StringLiteral
		and target_4.getArgument(4) instanceof Literal
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(EqualityOperation target_18, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vgroup_268, Parameter vorder_269, BlockStmt target_19, NotExpr target_21, NotExpr target_16) {
	exists(LogicalOrExpr target_6 |
		target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vorder_269
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder_269
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder_269
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder_269
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="field"
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_6.getParent().(IfStmt).getThen()=target_19
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(EqualityOperation target_12, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_7.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="111"
		and target_7.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="122"
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(EqualityOperation target_12, Function func) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vcofactor_269, EqualityOperation target_12, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_9.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_is_negative")
		and target_9.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcofactor_269
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="16"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="111"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="164"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_9)
		and target_9.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vgroup_268, Parameter vcofactor_269, ExprStmt target_22, NotExpr target_21, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const BIGNUM *")
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_is_zero")
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcofactor_269
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_269
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ec_guess_cofactor")
		and target_10.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_268
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_10.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_10)
		and target_10.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_11(Parameter vgroup_268, Parameter vorder_269, EqualityOperation target_18, IfStmt target_11) {
		target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="order"
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_11.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder_269
		and target_11.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_12(Parameter vcofactor_269, BlockStmt target_19, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vcofactor_269
		and target_12.getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen()=target_19
}

predicate func_13(Parameter vgroup_268, EqualityOperation target_12, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_13.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getCondition()=target_12
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0) instanceof IfStmt
}

predicate func_16(Parameter vgroup_268, Parameter vorder_269, NotExpr target_16) {
		target_16.getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_16.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="order"
		and target_16.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_16.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder_269
}

predicate func_18(Parameter vorder_269, EqualityOperation target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vorder_269
		and target_18.getAnOperand().(Literal).getValue()="0"
}

predicate func_19(Parameter vgroup_268, Parameter vcofactor_269, BlockStmt target_19) {
		target_19.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_19.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_19.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_19.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_269
		and target_19.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_21(Parameter vgroup_268, Parameter vcofactor_269, NotExpr target_21) {
		target_21.getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_21.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_21.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
		and target_21.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_269
}

predicate func_22(Parameter vgroup_268, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("BN_MONT_CTX_free")
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_268
}

from Function func, Parameter vgroup_268, Parameter vorder_269, Parameter vcofactor_269, VariableAccess target_0, FunctionCall target_1, IfStmt target_11, EqualityOperation target_12, ExprStmt target_13, BlockStmt target_15, NotExpr target_16, EqualityOperation target_18, BlockStmt target_19, NotExpr target_21, ExprStmt target_22
where
func_0(vorder_269, target_15, target_16, target_0)
and func_1(vgroup_268, target_1)
and not func_2(vgroup_268, target_15, target_16)
and not func_4(func)
and not func_5(target_18, func)
and not func_6(vgroup_268, vorder_269, target_19, target_21, target_16)
and not func_7(target_12, func)
and not func_8(target_12, func)
and not func_9(vcofactor_269, target_12, func)
and not func_10(vgroup_268, vcofactor_269, target_22, target_21, func)
and func_11(vgroup_268, vorder_269, target_18, target_11)
and func_12(vcofactor_269, target_19, target_12)
and func_13(vgroup_268, target_12, target_13)
and func_15(target_15)
and func_16(vgroup_268, vorder_269, target_16)
and func_18(vorder_269, target_18)
and func_19(vgroup_268, vcofactor_269, target_19)
and func_21(vgroup_268, vcofactor_269, target_21)
and func_22(vgroup_268, target_22)
and vgroup_268.getType().hasName("EC_GROUP *")
and vorder_269.getType().hasName("const BIGNUM *")
and vcofactor_269.getType().hasName("const BIGNUM *")
and vgroup_268.getParentScope+() = func
and vorder_269.getParentScope+() = func
and vcofactor_269.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
