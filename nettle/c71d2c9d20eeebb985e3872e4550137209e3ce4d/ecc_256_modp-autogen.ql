/**
 * @name nettle-c71d2c9d20eeebb985e3872e4550137209e3ce4d-ecc_256_modp
 * @id cpp/nettle/c71d2c9d20eeebb985e3872e4550137209e3ce4d/ecc-256-modp
 * @description nettle-c71d2c9d20eeebb985e3872e4550137209e3ce4d-ecc-256.c-ecc_256_modp CVE-2015-8803
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrp_73, Variable vn_76, Variable vt_85, Parameter vp_73, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_cnd_add_n")
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_85
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m"
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_73
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignSubExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vrp_73, Variable vn_76, Variable vt_85, Variable vcy_85, Parameter vp_73, ExprStmt target_7, ExprStmt target_11, ExprStmt target_8, ExprStmt target_9, ExprStmt target_12, ExprStmt target_10) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vcy_85
		and target_1.getRValue().(FunctionCall).getTarget().hasName("__gmpn_cnd_add_n")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_85
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_1.getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_1.getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_1.getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_1.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m"
		and target_1.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_73
		and target_1.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="2"
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignSubExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getLValue().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vu0_75, Variable vcy_85, ExprStmt target_13) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vu0_75
		and target_2.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcy_85
		and target_13.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_5(Variable vu1_75, Variable vu0_75, Variable vcy_85, ExprStmt target_12, ExprStmt target_9, ExprStmt target_11) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vu1_75
		and target_5.getExpr().(AssignAddExpr).getRValue().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vu0_75
		and target_5.getExpr().(AssignAddExpr).getRValue().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcy_85
		and target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignAddExpr).getRValue().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vrp_73, Variable vu1_75, Variable vn_76, Variable vt_85, Parameter vp_73, VariableAccess target_6) {
		target_6.getTarget()=vu1_75
		and target_6.getParent().(AssignAddExpr).getLValue() = target_6
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_cnd_add_n")
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vt_85
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="4"
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m"
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_73
		and target_6.getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_7(Parameter vrp_73, Variable vu0_75, Variable vn_76, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vu0_75
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrp_73
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vn_76
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_8(Variable vu1_75, Variable vt_85, Variable vcy_85, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_85
		and target_8.getExpr().(AssignExpr).getRValue().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vu1_75
		and target_8.getExpr().(AssignExpr).getRValue().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcy_85
}

predicate func_9(Variable vu1_75, Variable vt_85, ExprStmt target_9) {
		target_9.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vu1_75
		and target_9.getExpr().(AssignSubExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vt_85
		and target_9.getExpr().(AssignSubExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="4294967295"
}

predicate func_10(Parameter vrp_73, Variable vn_76, Variable vt_85, Parameter vp_73, ExprStmt target_10) {
		target_10.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vt_85
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("__gmpn_cnd_sub_n")
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="3"
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrp_73
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_76
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="3"
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="m"
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_73
		and target_10.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
}

predicate func_11(Parameter vrp_73, Variable vu0_75, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrp_73
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vu0_75
}

predicate func_12(Variable vu1_75, Variable vcy_85, ExprStmt target_12) {
		target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vu1_75
		and target_12.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vcy_85
}

predicate func_13(Variable vu0_75, Variable vt_85, ExprStmt target_13) {
		target_13.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vu0_75
		and target_13.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vt_85
}

from Function func, Parameter vrp_73, Variable vu1_75, Variable vu0_75, Variable vn_76, Variable vt_85, Variable vcy_85, Parameter vp_73, Literal target_0, VariableAccess target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
func_0(vrp_73, vn_76, vt_85, vp_73, target_7, target_8, target_9, target_10, target_0)
and not func_1(vrp_73, vn_76, vt_85, vcy_85, vp_73, target_7, target_11, target_8, target_9, target_12, target_10)
and not func_2(vu0_75, vcy_85, target_13)
and not func_5(vu1_75, vu0_75, vcy_85, target_12, target_9, target_11)
and func_6(vrp_73, vu1_75, vn_76, vt_85, vp_73, target_6)
and func_7(vrp_73, vu0_75, vn_76, target_7)
and func_8(vu1_75, vt_85, vcy_85, target_8)
and func_9(vu1_75, vt_85, target_9)
and func_10(vrp_73, vn_76, vt_85, vp_73, target_10)
and func_11(vrp_73, vu0_75, target_11)
and func_12(vu1_75, vcy_85, target_12)
and func_13(vu0_75, vt_85, target_13)
and vrp_73.getType().hasName("mp_limb_t *")
and vu1_75.getType().hasName("mp_limb_t")
and vu0_75.getType().hasName("mp_limb_t")
and vn_76.getType().hasName("mp_size_t")
and vt_85.getType().hasName("mp_limb_t")
and vcy_85.getType().hasName("mp_limb_t")
and vp_73.getType().hasName("const ecc_modulo *")
and vrp_73.getParentScope+() = func
and vu1_75.getParentScope+() = func
and vu0_75.getParentScope+() = func
and vn_76.getParentScope+() = func
and vt_85.getParentScope+() = func
and vcy_85.getParentScope+() = func
and vp_73.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
