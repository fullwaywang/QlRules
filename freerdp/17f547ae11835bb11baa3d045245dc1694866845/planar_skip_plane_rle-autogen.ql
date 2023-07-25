/**
 * @name freerdp-17f547ae11835bb11baa3d045245dc1694866845-planar_skip_plane_rle
 * @id cpp/freerdp/17f547ae11835bb11baa3d045245dc1694866845/planar-skip-plane-rle
 * @description freerdp-17f547ae11835bb11baa3d045245dc1694866845-libfreerdp/codec/planar.c-planar_skip_plane_rle CVE-2020-11521
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpSrcData_42, Initializer target_0) {
		target_0.getExpr().(VariableAccess).getTarget()=vpSrcData_42
}

predicate func_4(Parameter vpSrcData_42, PointerArithmeticOperation target_21) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(VariableAccess).getTarget()=vpSrcData_42
		and target_4.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("UINT32")
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getArrayBase().(VariableAccess).getLocation().isBefore(target_21.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vcRawBytes_54, ExprStmt target_22, ExprStmt target_23) {
	exists(AssignAddExpr target_5 |
		target_5.getLValue().(VariableAccess).getType().hasName("UINT32")
		and target_5.getRValue().(VariableAccess).getTarget()=vcRawBytes_54
		and target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getRValue().(VariableAccess).getLocation())
		and target_5.getRValue().(VariableAccess).getLocation().isBefore(target_23.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_8(Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("UINT32")
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_8.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_8))
}

/*predicate func_10(Parameter vpSrcData_42, Parameter vSrcSize_42, VariableAccess target_10) {
		target_10.getTarget()=vpSrcData_42
		and target_10.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vSrcSize_42
}

*/
predicate func_11(Variable vcRawBytes_54, VariableAccess target_11) {
		target_11.getTarget()=vcRawBytes_54
}

/*predicate func_12(Parameter vpSrcData_42, Parameter vSrcSize_42, VariableAccess target_12) {
		target_12.getTarget()=vSrcSize_42
		and target_12.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpSrcData_42
}

*/
predicate func_14(Function func, DeclStmt target_14) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable vpRLE_47, Variable vpEnd_48, ReturnStmt target_24, RelationalOperation target_26, VariableAccess target_15) {
		target_15.getTarget()=vpRLE_47
		and target_15.getParent().(GEExpr).getLesserOperand().(VariableAccess).getTarget()=vpEnd_48
		and target_15.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
		and target_15.getParent().(GEExpr).getLesserOperand().(VariableAccess).getLocation().isBefore(target_26.getLesserOperand().(VariableAccess).getLocation())
}

/*predicate func_16(Variable vpEnd_48, ReturnStmt target_24, RelationalOperation target_26, VariableAccess target_16) {
		target_16.getTarget()=vpEnd_48
		and target_16.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_24
		and target_16.getLocation().isBefore(target_26.getLesserOperand().(VariableAccess).getLocation())
}

*/
predicate func_17(Variable vpRLE_47, PointerDereferenceExpr target_17) {
		target_17.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vpRLE_47
		and target_17.getParent().(AssignExpr).getRValue() = target_17
}

predicate func_18(Variable vpRLE_47, Variable vcRawBytes_54, AssignPointerAddExpr target_18) {
		target_18.getLValue().(VariableAccess).getTarget()=vpRLE_47
		and target_18.getRValue().(VariableAccess).getTarget()=vcRawBytes_54
}

/*predicate func_19(Variable vpRLE_47, Variable vpEnd_48, ReturnStmt target_27, PointerArithmeticOperation target_21, RelationalOperation target_29, VariableAccess target_19) {
		target_19.getTarget()=vpRLE_47
		and target_19.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vpEnd_48
		and target_19.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_27
		and target_19.getLocation().isBefore(target_21.getLeftOperand().(VariableAccess).getLocation())
		and target_29.getLesserOperand().(VariableAccess).getLocation().isBefore(target_19.getParent().(GTExpr).getLesserOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_20(Variable vpRLE_47, Variable vpEnd_48, ReturnStmt target_27, PointerArithmeticOperation target_21, RelationalOperation target_29, VariableAccess target_20) {
		target_20.getTarget()=vpEnd_48
		and target_20.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vpRLE_47
		and target_20.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_27
		and target_20.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_21.getLeftOperand().(VariableAccess).getLocation())
		and target_29.getLesserOperand().(VariableAccess).getLocation().isBefore(target_20.getLocation())
}

*/
predicate func_21(Variable vpRLE_47, Parameter vpSrcData_42, PointerArithmeticOperation target_21) {
		target_21.getLeftOperand().(VariableAccess).getTarget()=vpRLE_47
		and target_21.getRightOperand().(VariableAccess).getTarget()=vpSrcData_42
}

predicate func_22(Variable vcRawBytes_54, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcRawBytes_54
		and target_22.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_23(Variable vcRawBytes_54, ExprStmt target_23) {
		target_23.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vcRawBytes_54
}

predicate func_24(ReturnStmt target_24) {
		target_24.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_26(Variable vpRLE_47, Variable vpEnd_48, RelationalOperation target_26) {
		 (target_26 instanceof GTExpr or target_26 instanceof LTExpr)
		and target_26.getGreaterOperand().(VariableAccess).getTarget()=vpRLE_47
		and target_26.getLesserOperand().(VariableAccess).getTarget()=vpEnd_48
}

predicate func_27(ReturnStmt target_27) {
		target_27.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_29(Variable vpRLE_47, Variable vpEnd_48, RelationalOperation target_29) {
		 (target_29 instanceof GEExpr or target_29 instanceof LEExpr)
		and target_29.getGreaterOperand().(VariableAccess).getTarget()=vpRLE_47
		and target_29.getLesserOperand().(VariableAccess).getTarget()=vpEnd_48
}

from Function func, Variable vpRLE_47, Variable vpEnd_48, Variable vcRawBytes_54, Parameter vpSrcData_42, Parameter vSrcSize_42, Initializer target_0, VariableAccess target_11, DeclStmt target_14, VariableAccess target_15, PointerDereferenceExpr target_17, AssignPointerAddExpr target_18, PointerArithmeticOperation target_21, ExprStmt target_22, ExprStmt target_23, ReturnStmt target_24, RelationalOperation target_26, ReturnStmt target_27, RelationalOperation target_29
where
func_0(vpSrcData_42, target_0)
and not func_4(vpSrcData_42, target_21)
and not func_5(vcRawBytes_54, target_22, target_23)
and not func_8(func)
and func_11(vcRawBytes_54, target_11)
and func_14(func, target_14)
and func_15(vpRLE_47, vpEnd_48, target_24, target_26, target_15)
and func_17(vpRLE_47, target_17)
and func_18(vpRLE_47, vcRawBytes_54, target_18)
and func_21(vpRLE_47, vpSrcData_42, target_21)
and func_22(vcRawBytes_54, target_22)
and func_23(vcRawBytes_54, target_23)
and func_24(target_24)
and func_26(vpRLE_47, vpEnd_48, target_26)
and func_27(target_27)
and func_29(vpRLE_47, vpEnd_48, target_29)
and vpRLE_47.getType().hasName("const BYTE *")
and vpEnd_48.getType().hasName("const BYTE *")
and vcRawBytes_54.getType().hasName("int")
and vpSrcData_42.getType().hasName("const BYTE *")
and vSrcSize_42.getType().hasName("UINT32")
and vpRLE_47.getParentScope+() = func
and vpEnd_48.getParentScope+() = func
and vcRawBytes_54.getParentScope+() = func
and vpSrcData_42.getParentScope+() = func
and vSrcSize_42.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
