import torch.nn as nn
import torch.nn.functional as F
import itertools

__all__ = ["ResNet9"]

class Mul(nn.Module):
    def __init__(self, weight):
        super().__init__()
        self.weight = weight

    def __call__(self, x):
        return x * self.weight

def batch_norm(num_channels, bn_bias_init=None, bn_bias_freeze=False,
               bn_weight_init=None, bn_weight_freeze=False):
    m = nn.BatchNorm2d(num_channels)
    if bn_bias_init is not None:
        m.bias.data.fill_(bn_bias_init)
    if bn_bias_freeze:
        m.bias.requires_grad = False
    if bn_weight_init is not None:
        m.weight.data.fill_(bn_weight_init)
    if bn_weight_freeze:
        m.weight.requires_grad = False
    return m

class ConvBN(nn.Module):
    def __init__(self, do_batchnorm, c_in, c_out, bn_weight_init=1.0, pool=None, **kw):
        super().__init__()
        self.pool = pool
        self.conv = nn.Conv2d(c_in, c_out, kernel_size=(3, 3), stride=(1, 1),
                              padding=1, bias=False)
        if do_batchnorm:
            self.bn = batch_norm(c_out, bn_weight_init=bn_weight_init, **kw)
        self.do_batchnorm = do_batchnorm
        self.relu = nn.ReLU(True)
    
    def forward(self, x):
        if self.do_batchnorm:
            out = self.relu(self.bn(self.conv(x)))
        else:
            out = self.relu(self.conv(x))
        if self.pool:
            out = self.pool(out)
        return out

class Residual(nn.Module):
    def __init__(self, do_batchnorm, c, **kw):
        super().__init__()
        self.res1 = ConvBN(do_batchnorm, c, c, **kw)
        self.res2 = ConvBN(do_batchnorm, c, c, **kw)

    def forward(self, x):
        return x + F.relu(self.res2(self.res1(x)))

class BasicNet(nn.Module):
    def __init__(self, do_batchnorm, channels, weight, pool, num_classes=10, initial_channels=1, **kw):
        super().__init__()
        self.prep = ConvBN(do_batchnorm, initial_channels, channels['prep'], **kw)
        self.layer1 = ConvBN(do_batchnorm, channels['prep'], channels['layer1'], pool=pool, **kw)
        self.res1 = Residual(do_batchnorm, channels['layer1'], **kw)
        self.layer2 = ConvBN(do_batchnorm, channels['layer1'], channels['layer2'], pool=pool, **kw)
        self.layer3 = ConvBN(do_batchnorm, channels['layer2'], channels['layer3'], pool=pool, **kw)
        self.res3 = Residual(do_batchnorm, channels['layer3'], **kw)

        self.pool = nn.MaxPool2d(2, 2)  #########
        # self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.linear = nn.Linear(channels['layer3'], num_classes, bias=False)
        self.classifier = Mul(weight)

    def forward(self, x):
        out = self.prep(x)
        out = self.res1(self.layer1(out))
        out = self.layer2(out)
        out = self.res3(self.layer3(out))

        out = self.pool(out).view(out.size()[0], -1)
        out = self.classifier(self.linear(out))
        return out

class ResNet9(nn.Module):
    def __init__(self, do_batchnorm=True, channels=None, weight=0.125, pool=nn.MaxPool2d(2), num_classes=10, **kw):
        super().__init__()
        self.channels = {'prep': 64, 'layer1': 128, 'layer2': 256, 'layer3': 512}
        self.weight = weight
        self.pool = pool
        print(f"Using BatchNorm: {do_batchnorm}")
        self.n = BasicNet(do_batchnorm, self.channels, weight, pool, num_classes, **kw)

    def forward(self, x):
        return self.n(x)
