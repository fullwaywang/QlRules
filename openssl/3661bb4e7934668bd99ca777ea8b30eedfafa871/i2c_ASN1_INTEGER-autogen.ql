/**
 * @name openssl-3661bb4e7934668bd99ca777ea8b30eedfafa871-i2c_ASN1_INTEGER
 * @id cpp/openssl/3661bb4e7934668bd99ca777ea8b30eedfafa871/i2c-ASN1-INTEGER
 * @description openssl-3661bb4e7934668bd99ca777ea8b30eedfafa871-i2c_ASN1_INTEGER NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter va_114, Variable vi_116, Variable vp_117, Variable vn_117) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof NotExpr
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_117
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_117
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_117
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_2.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vn_117
		and target_2.getElse().(BlockStmt).getStmt(3).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vp_117
		and target_2.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseXorExpr).getRightOperand().(HexLiteral).getValue()="255"
		and target_2.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getElse().(BlockStmt).getStmt(6).(ForStmt).getUpdate().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_116
		and target_2.getElse().(BlockStmt).getStmt(6).(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getRightOperand().(HexLiteral).getValue()="255"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_4(Parameter va_114, Variable vneg_116, Variable vp_117) {
	exists(NotExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vneg_116
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_117
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114)
}

predicate func_5(Variable vn_117) {
	exists(NotExpr target_5 |
		target_5.getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vn_117)
}

predicate func_6(Parameter vpp_114, Variable vret_116) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getTarget()=vret_116
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpp_114
		and target_6.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_7(Parameter va_114, Variable vpad_116, Variable vi_116, Variable vpb_117) {
	exists(ArrayExpr target_7 |
		target_7.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114
		and target_7.getArrayOffset().(VariableAccess).getTarget()=vi_116
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpad_116
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpb_117
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="255"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;")
}

predicate func_8(Parameter va_114, Variable vi_116) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(VariableAccess).getTarget()=vi_116
		and target_8.getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_8.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_114)
}

from Function func, Parameter va_114, Parameter vpp_114, Variable vpad_116, Variable vret_116, Variable vi_116, Variable vneg_116, Variable vp_117, Variable vn_117, Variable vpb_117
where
not func_2(va_114, vi_116, vp_117, vn_117)
and func_4(va_114, vneg_116, vp_117)
and func_5(vn_117)
and va_114.getType().hasName("ASN1_INTEGER *")
and vret_116.getType().hasName("int")
and func_6(vpp_114, vret_116)
and vi_116.getType().hasName("int")
and func_7(va_114, vpad_116, vi_116, vpb_117)
and func_8(va_114, vi_116)
and vneg_116.getType().hasName("int")
and vp_117.getType().hasName("unsigned char *")
and vn_117.getType().hasName("unsigned char *")
and vpb_117.getType().hasName("unsigned char")
and va_114.getParentScope+() = func
and vpp_114.getParentScope+() = func
and vpad_116.getParentScope+() = func
and vret_116.getParentScope+() = func
and vi_116.getParentScope+() = func
and vneg_116.getParentScope+() = func
and vp_117.getParentScope+() = func
and vn_117.getParentScope+() = func
and vpb_117.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
