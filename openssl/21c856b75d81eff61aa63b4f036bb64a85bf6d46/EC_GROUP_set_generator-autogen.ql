/**
 * @name openssl-21c856b75d81eff61aa63b4f036bb64a85bf6d46-EC_GROUP_set_generator
 * @id cpp/openssl/21c856b75d81eff61aa63b4f036bb64a85bf6d46/EC-GROUP-set-generator
 * @description openssl-21c856b75d81eff61aa63b4f036bb64a85bf6d46-crypto/ec/ec_lib.c-EC_GROUP_set_generator CVE-2019-1547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vorder_298, BlockStmt target_16, NotExpr target_17, VariableAccess target_0) {
		target_0.getTarget()=vorder_298
		and target_0.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_16
		and target_0.getLocation().isBefore(target_17.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

/*predicate func_1(Parameter vgroup_297, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="order"
		and target_1.getQualifier().(VariableAccess).getTarget()=vgroup_297
}

*/
predicate func_2(Parameter vgroup_297, FunctionCall target_2) {
		target_2.getTarget().hasName("BN_set_word")
		and not target_2.getTarget().hasName("BN_num_bits")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_2.getArgument(1) instanceof Literal
}

predicate func_3(Parameter vgroup_297, BlockStmt target_16, AddressOfExpr target_18) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_3.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="neg"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="field"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_16
		and target_18.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("ERR_put_error")
		and target_4.getArgument(0) instanceof Literal
		and target_4.getArgument(1) instanceof Literal
		and target_4.getArgument(2) instanceof Literal
		and target_4.getArgument(3) instanceof StringLiteral
		and target_4.getArgument(4) instanceof Literal
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(EqualityOperation target_19, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vgroup_297, Parameter vorder_298, BlockStmt target_20, AddressOfExpr target_21, AddressOfExpr target_22) {
	exists(LogicalOrExpr target_6 |
		target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vorder_298
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorder_298
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="neg"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorder_298
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vorder_298
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("BN_num_bits")
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="field"
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_6.getParent().(IfStmt).getThen()=target_20
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(EqualityOperation target_13, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_8.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(EqualityOperation target_13, Function func) {
	exists(ReturnStmt target_9 |
		target_9.getExpr().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vcofactor_298, EqualityOperation target_13, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="neg"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcofactor_298
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_10.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_10)
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_11(Parameter vgroup_297, Parameter vcofactor_298, ExprStmt target_23, NotExpr target_24, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("const BIGNUM *")
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="top"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcofactor_298
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_298
		and target_11.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_11.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ec_guess_cofactor")
		and target_11.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgroup_297
		and target_11.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_11.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_11)
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getElse().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_24.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Parameter vgroup_297, Parameter vorder_298, EqualityOperation target_19, IfStmt target_12) {
		target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder_298
		and target_12.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_13(Parameter vcofactor_298, BlockStmt target_20, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vcofactor_298
		and target_13.getAnOperand().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getThen()=target_20
}

predicate func_14(Parameter vgroup_297, EqualityOperation target_13, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("BN_set_word")
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getCondition()=target_13
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0) instanceof IfStmt
}

predicate func_17(Parameter vgroup_297, Parameter vorder_298, NotExpr target_17) {
		target_17.getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_17.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_17.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_17.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorder_298
}

predicate func_18(Parameter vgroup_297, AddressOfExpr target_18) {
		target_18.getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_18.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
}

predicate func_19(Parameter vorder_298, EqualityOperation target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vorder_298
		and target_19.getAnOperand().(Literal).getValue()="0"
}

predicate func_20(Parameter vgroup_297, Parameter vcofactor_298, BlockStmt target_20) {
		target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_298
		and target_20.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_21(Parameter vgroup_297, AddressOfExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="order"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
}

predicate func_22(Parameter vgroup_297, AddressOfExpr target_22) {
		target_22.getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
}

predicate func_23(Parameter vgroup_297, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_23.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_23.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_24(Parameter vgroup_297, Parameter vcofactor_298, NotExpr target_24) {
		target_24.getOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_24.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cofactor"
		and target_24.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_297
		and target_24.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcofactor_298
}

from Function func, Parameter vgroup_297, Parameter vorder_298, Parameter vcofactor_298, VariableAccess target_0, FunctionCall target_2, IfStmt target_12, EqualityOperation target_13, ExprStmt target_14, BlockStmt target_16, NotExpr target_17, AddressOfExpr target_18, EqualityOperation target_19, BlockStmt target_20, AddressOfExpr target_21, AddressOfExpr target_22, ExprStmt target_23, NotExpr target_24
where
func_0(vorder_298, target_16, target_17, target_0)
and func_2(vgroup_297, target_2)
and not func_3(vgroup_297, target_16, target_18)
and not func_4(func)
and not func_5(target_19, func)
and not func_6(vgroup_297, vorder_298, target_20, target_21, target_22)
and not func_8(target_13, func)
and not func_9(target_13, func)
and not func_10(vcofactor_298, target_13, func)
and not func_11(vgroup_297, vcofactor_298, target_23, target_24, func)
and func_12(vgroup_297, vorder_298, target_19, target_12)
and func_13(vcofactor_298, target_20, target_13)
and func_14(vgroup_297, target_13, target_14)
and func_16(target_16)
and func_17(vgroup_297, vorder_298, target_17)
and func_18(vgroup_297, target_18)
and func_19(vorder_298, target_19)
and func_20(vgroup_297, vcofactor_298, target_20)
and func_21(vgroup_297, target_21)
and func_22(vgroup_297, target_22)
and func_23(vgroup_297, target_23)
and func_24(vgroup_297, vcofactor_298, target_24)
and vgroup_297.getType().hasName("EC_GROUP *")
and vorder_298.getType().hasName("const BIGNUM *")
and vcofactor_298.getType().hasName("const BIGNUM *")
and vgroup_297.getParentScope+() = func
and vorder_298.getParentScope+() = func
and vcofactor_298.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
