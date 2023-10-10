/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-TIFFRGBAImageOK
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/TIFFRGBAImageOK
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-libtiff/tif_getimage.c-TIFFRGBAImageOK CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vemsg_76, Variable vtd_78, VariableAccess target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemsg_76
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Sorry, can not handle image with %s=%d"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Samples/pixel"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vemsg_76, Variable vtd_78, VariableAccess target_2, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemsg_76
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Sorry, can not handle image with %s=%d and %s=%d"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Samples/pixel"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_samplesperpixel"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Bits/sample"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="td_bitspersample"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vphotometric_79, VariableAccess target_2) {
		target_2.getTarget()=vphotometric_79
}

predicate func_3(Parameter vemsg_76, Variable vtd_78, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemsg_76
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Sorry, can not handle LogLuv images with %s=%d"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Planarconfiguration"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="td_planarconfig"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_78
}

predicate func_4(Parameter vemsg_76, Variable vphotometric_79, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("sprintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vemsg_76
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Sorry, can not handle image with %s=%d"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vphotometric_79
}

from Function func, Parameter vemsg_76, Variable vtd_78, Variable vphotometric_79, VariableAccess target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vemsg_76, vtd_78, target_2, target_3)
and not func_1(vemsg_76, vtd_78, target_2, target_4)
and func_2(vphotometric_79, target_2)
and func_3(vemsg_76, vtd_78, target_3)
and func_4(vemsg_76, vphotometric_79, target_4)
and vemsg_76.getType().hasName("char[1024]")
and vtd_78.getType().hasName("TIFFDirectory *")
and vphotometric_79.getType().hasName("uint16")
and vemsg_76.getFunction() = func
and vtd_78.(LocalVariable).getFunction() = func
and vphotometric_79.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
