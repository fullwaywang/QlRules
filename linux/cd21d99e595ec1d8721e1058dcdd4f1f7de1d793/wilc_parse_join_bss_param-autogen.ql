/**
 * @name linux-cd21d99e595ec1d8721e1058dcdd4f1f7de1d793-wilc_parse_join_bss_param
 * @id cpp/linux/cd21d99e595ec1d8721e1058dcdd4f1f7de1d793/wilc_parse_join_bss_param
 * @description linux-cd21d99e595ec1d8721e1058dcdd4f1f7de1d793-wilc_parse_join_bss_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vrsn_ie_381) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="2"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrsn_ie_381
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_1(Variable vrsn_ie_381, Variable voffset_485) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_485
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_485
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_485
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_4(Variable vparam_377, Variable vrsn_ie_381) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mode_802_11i"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_377
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_5(Variable vparam_377, Variable vrsn_ie_381) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rsn_found"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_377
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_6(Variable vrsn_ie_381, Variable voffset_485) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_485
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrsn_ie_381
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=voffset_485
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_8(Variable vparam_377, Variable vrsn_ie_381, Variable voffset_485) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rsn_cap"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_377
		and target_8.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrsn_ie_381
		and target_8.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=voffset_485
		and target_8.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vrsn_ie_381)
}

predicate func_9(Variable vrsn_ie_381, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(VariableAccess).getTarget()=vrsn_ie_381
		and target_9.getThen().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="8"
		and target_9.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_9.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Variable vparam_377, Variable vrsn_ie_381, Variable voffset_485
where
not func_0(vrsn_ie_381)
and not func_1(vrsn_ie_381, voffset_485)
and func_4(vparam_377, vrsn_ie_381)
and func_5(vparam_377, vrsn_ie_381)
and func_6(vrsn_ie_381, voffset_485)
and func_8(vparam_377, vrsn_ie_381, voffset_485)
and vparam_377.getType().hasName("wilc_join_bss_param *")
and vrsn_ie_381.getType().hasName("const u8 *")
and func_9(vrsn_ie_381, func)
and voffset_485.getType().hasName("int")
and vparam_377.getParentScope+() = func
and vrsn_ie_381.getParentScope+() = func
and voffset_485.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
